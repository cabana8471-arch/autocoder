"""
Expand Chat Session
===================

Manages interactive project expansion conversation with Claude.
Uses the expand-project.md skill to help users add features to existing projects.
"""

import json
import logging
import re
import shutil
import threading
from datetime import datetime
from pathlib import Path
from typing import AsyncGenerator, Optional

from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient

from ..schemas import ImageAttachment

logger = logging.getLogger(__name__)


async def _make_multimodal_message(content_blocks: list[dict]) -> AsyncGenerator[dict, None]:
    """
    Create an async generator that yields a properly formatted multimodal message.
    """
    yield {
        "type": "user",
        "message": {"role": "user", "content": content_blocks},
        "parent_tool_use_id": None,
        "session_id": "default",
    }


# Root directory of the project
ROOT_DIR = Path(__file__).parent.parent.parent


class ExpandChatSession:
    """
    Manages a project expansion conversation.

    Unlike SpecChatSession which writes spec files, this session:
    1. Reads existing app_spec.txt for context
    2. Parses feature definitions from Claude's output
    3. Creates features via REST API
    4. Tracks which features were created during the session
    """

    def __init__(self, project_name: str, project_dir: Path):
        """
        Initialize the session.

        Args:
            project_name: Name of the project being expanded
            project_dir: Absolute path to the project directory
        """
        self.project_name = project_name
        self.project_dir = project_dir
        self.client: Optional[ClaudeSDKClient] = None
        self.messages: list[dict] = []
        self.complete: bool = False
        self.created_at = datetime.now()
        self._conversation_id: Optional[str] = None
        self._client_entered: bool = False
        self.features_created: int = 0
        self.created_feature_ids: list[int] = []

    async def close(self) -> None:
        """Clean up resources and close the Claude client."""
        if self.client and self._client_entered:
            try:
                await self.client.__aexit__(None, None, None)
            except Exception as e:
                logger.warning(f"Error closing Claude client: {e}")
            finally:
                self._client_entered = False
                self.client = None

    async def start(self) -> AsyncGenerator[dict, None]:
        """
        Initialize session and get initial greeting from Claude.

        Yields message chunks as they stream in.
        """
        # Load the expand-project skill
        skill_path = ROOT_DIR / ".claude" / "commands" / "expand-project.md"

        if not skill_path.exists():
            yield {
                "type": "error",
                "content": f"Expand project skill not found at {skill_path}"
            }
            return

        # Verify project has existing spec
        spec_path = self.project_dir / "prompts" / "app_spec.txt"
        if not spec_path.exists():
            yield {
                "type": "error",
                "content": "Project has no app_spec.txt. Please create it first using spec creation."
            }
            return

        try:
            skill_content = skill_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            skill_content = skill_path.read_text(encoding="utf-8", errors="replace")

        # Create security settings file
        security_settings = {
            "sandbox": {"enabled": False},
            "permissions": {
                "defaultMode": "acceptEdits",
                "allow": [
                    "Read(./**)",
                    "Glob(./**)",
                ],
            },
        }
        settings_file = self.project_dir / ".claude_settings.json"
        with open(settings_file, "w") as f:
            json.dump(security_settings, f, indent=2)

        # Replace $ARGUMENTS with absolute project path
        project_path = str(self.project_dir.resolve())
        system_prompt = skill_content.replace("$ARGUMENTS", project_path)

        # Create Claude SDK client
        system_cli = shutil.which("claude")
        try:
            self.client = ClaudeSDKClient(
                options=ClaudeAgentOptions(
                    model="claude-opus-4-5-20251101",
                    cli_path=system_cli,
                    system_prompt=system_prompt,
                    allowed_tools=[
                        "Read",
                        "Glob",
                    ],
                    permission_mode="acceptEdits",
                    max_turns=100,
                    cwd=str(self.project_dir.resolve()),
                    settings=str(settings_file.resolve()),
                )
            )
            await self.client.__aenter__()
            self._client_entered = True
        except Exception as e:
            logger.exception("Failed to create Claude client")
            yield {
                "type": "error",
                "content": f"Failed to initialize Claude: {str(e)}"
            }
            return

        # Start the conversation
        try:
            async for chunk in self._query_claude("Begin the project expansion process."):
                yield chunk
            yield {"type": "response_done"}
        except Exception as e:
            logger.exception("Failed to start expand chat")
            yield {
                "type": "error",
                "content": f"Failed to start conversation: {str(e)}"
            }

    async def send_message(
        self,
        user_message: str,
        attachments: list[ImageAttachment] | None = None
    ) -> AsyncGenerator[dict, None]:
        """
        Send user message and stream Claude's response.

        Args:
            user_message: The user's response
            attachments: Optional list of image attachments

        Yields:
            Message chunks of various types:
            - {"type": "text", "content": str}
            - {"type": "features_created", "count": N, "features": [...]}
            - {"type": "expansion_complete", "total_added": N}
            - {"type": "error", "content": str}
        """
        if not self.client:
            yield {
                "type": "error",
                "content": "Session not initialized. Call start() first."
            }
            return

        # Store the user message
        self.messages.append({
            "role": "user",
            "content": user_message,
            "has_attachments": bool(attachments),
            "timestamp": datetime.now().isoformat()
        })

        try:
            async for chunk in self._query_claude(user_message, attachments):
                yield chunk
            yield {"type": "response_done"}
        except Exception as e:
            logger.exception("Error during Claude query")
            yield {
                "type": "error",
                "content": f"Error: {str(e)}"
            }

    async def _query_claude(
        self,
        message: str,
        attachments: list[ImageAttachment] | None = None
    ) -> AsyncGenerator[dict, None]:
        """
        Internal method to query Claude and stream responses.

        Handles text responses and detects feature creation blocks.
        """
        if not self.client:
            return

        # Build the message content
        if attachments and len(attachments) > 0:
            content_blocks = []
            if message:
                content_blocks.append({"type": "text", "text": message})
            for att in attachments:
                content_blocks.append({
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": att.mimeType,
                        "data": att.base64Data,
                    }
                })
            await self.client.query(_make_multimodal_message(content_blocks))
            logger.info(f"Sent multimodal message with {len(attachments)} image(s)")
        else:
            await self.client.query(message)

        # Accumulate full response to detect feature blocks
        full_response = ""

        # Stream the response
        async for msg in self.client.receive_response():
            msg_type = type(msg).__name__

            if msg_type == "AssistantMessage" and hasattr(msg, "content"):
                for block in msg.content:
                    block_type = type(block).__name__

                    if block_type == "TextBlock" and hasattr(block, "text"):
                        text = block.text
                        if text:
                            full_response += text
                            yield {"type": "text", "content": text}

                            self.messages.append({
                                "role": "assistant",
                                "content": text,
                                "timestamp": datetime.now().isoformat()
                            })

        # Check for feature creation block in full response
        features_match = re.search(
            r'<features_to_create>\s*(\[[\s\S]*?\])\s*</features_to_create>',
            full_response
        )

        if features_match:
            try:
                features_json = features_match.group(1)
                features_data = json.loads(features_json)

                if features_data and isinstance(features_data, list):
                    # Create features via REST API
                    created = await self._create_features_bulk(features_data)

                    if created:
                        self.features_created += len(created)
                        self.created_feature_ids.extend([f["id"] for f in created])

                        yield {
                            "type": "features_created",
                            "count": len(created),
                            "features": created
                        }

                        logger.info(f"Created {len(created)} features for {self.project_name}")
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse features JSON: {e}")
                yield {
                    "type": "error",
                    "content": f"Failed to parse feature definitions: {str(e)}"
                }
            except Exception as e:
                logger.exception("Failed to create features")
                yield {
                    "type": "error",
                    "content": f"Failed to create features: {str(e)}"
                }

    async def _create_features_bulk(self, features: list[dict]) -> list[dict]:
        """
        Create features directly in the database.

        Args:
            features: List of feature dictionaries with category, name, description, steps

        Returns:
            List of created feature dictionaries with IDs
        """
        # Import database classes
        import sys
        root = Path(__file__).parent.parent.parent
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))

        from api.database import Feature, create_database

        # Get database session
        _, SessionLocal = create_database(self.project_dir)
        session = SessionLocal()

        try:
            # Determine starting priority
            max_priority_feature = session.query(Feature).order_by(Feature.priority.desc()).first()
            current_priority = (max_priority_feature.priority + 1) if max_priority_feature else 1

            created_features = []

            for f in features:
                db_feature = Feature(
                    priority=current_priority,
                    category=f.get("category", "functional"),
                    name=f.get("name", "Unnamed feature"),
                    description=f.get("description", ""),
                    steps=f.get("steps", []),
                    passes=False,
                )
                session.add(db_feature)
                current_priority += 1

            session.commit()

            # Re-query to get the created features with IDs
            start_priority = current_priority - len(features)
            for db_feature in session.query(Feature).filter(
                Feature.priority >= start_priority,
                Feature.priority < current_priority
            ).order_by(Feature.priority).all():
                created_features.append({
                    "id": db_feature.id,
                    "name": db_feature.name,
                    "category": db_feature.category,
                })

            return created_features

        finally:
            session.close()

    def get_features_created(self) -> int:
        """Get the total number of features created in this session."""
        return self.features_created

    def is_complete(self) -> bool:
        """Check if expansion session is complete."""
        return self.complete

    def get_messages(self) -> list[dict]:
        """Get all messages in the conversation."""
        return self.messages.copy()


# Session registry with thread safety
_expand_sessions: dict[str, ExpandChatSession] = {}
_expand_sessions_lock = threading.Lock()


def get_expand_session(project_name: str) -> Optional[ExpandChatSession]:
    """Get an existing expansion session for a project."""
    with _expand_sessions_lock:
        return _expand_sessions.get(project_name)


async def create_expand_session(project_name: str, project_dir: Path) -> ExpandChatSession:
    """Create a new expansion session for a project, closing any existing one."""
    old_session: Optional[ExpandChatSession] = None

    with _expand_sessions_lock:
        old_session = _expand_sessions.pop(project_name, None)
        session = ExpandChatSession(project_name, project_dir)
        _expand_sessions[project_name] = session

    if old_session:
        try:
            await old_session.close()
        except Exception as e:
            logger.warning(f"Error closing old expand session for {project_name}: {e}")

    return session


async def remove_expand_session(project_name: str) -> None:
    """Remove and close an expansion session."""
    session: Optional[ExpandChatSession] = None

    with _expand_sessions_lock:
        session = _expand_sessions.pop(project_name, None)

    if session:
        try:
            await session.close()
        except Exception as e:
            logger.warning(f"Error closing expand session for {project_name}: {e}")


def list_expand_sessions() -> list[str]:
    """List all active expansion session project names."""
    with _expand_sessions_lock:
        return list(_expand_sessions.keys())


async def cleanup_all_expand_sessions() -> None:
    """Close all active expansion sessions. Called on server shutdown."""
    sessions_to_close: list[ExpandChatSession] = []

    with _expand_sessions_lock:
        sessions_to_close = list(_expand_sessions.values())
        _expand_sessions.clear()

    for session in sessions_to_close:
        try:
            await session.close()
        except Exception as e:
            logger.warning(f"Error closing expand session {session.project_name}: {e}")
