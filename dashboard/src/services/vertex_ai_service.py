from __future__ import annotations

import logging
from typing import Any

from src.core.config import VertexAIConfig
from src.schemas.metrics import EvaluateResponse

logger = logging.getLogger(__name__)

_COMPLIANCE_PROMPT = """You are a compliance evaluator. Given a project constitution and an artifact,
score how well the artifact adheres to the constitution's principles on a scale of 0-100.
Return ONLY a JSON object: {{"score": <number>, "passed": <boolean>, "failures": [<string>, ...]}}

Constitution:
{constitution}

Artifact:
{artifact}"""

_ARTIFACT_PROMPT = """You are a quality evaluator. Given a rubric and an artifact,
score the artifact's quality on a scale of 0-100.
Return ONLY a JSON object: {{"score": <number>, "passed": <boolean>, "failures": [<string>, ...]}}

Rubric:
{rubric}

Artifact:
{artifact}"""

_HARNESS_PROMPT = """You are a code quality judge. Evaluate the following code output
against the acceptance criteria. Score 0-100.
Return ONLY a JSON object: {{"score": <number>, "passed": <boolean>, "failures": [<string>, ...]}}

Criteria:
{rubric}

Code:
{content}"""


class VertexAIService:
    def __init__(self, config: VertexAIConfig) -> None:
        self._config = config
        self._client: Any = None

    async def _get_model(self) -> Any:
        if not self._config.enabled:
            return None
        if self._client is None:
            try:
                import vertexai
                from vertexai.generative_models import GenerativeModel

                vertexai.init(
                    project=self._config.project_id,
                    location=self._config.location,
                )
                self._client = GenerativeModel(self._config.model_id)
            except Exception:
                logger.exception("Failed to initialize Vertex AI")
                return None
        return self._client

    async def evaluate(
        self,
        eval_type: str,
        content: str,
        rubric: str | None = None,
    ) -> EvaluateResponse:
        model = await self._get_model()
        if model is None:
            return EvaluateResponse(
                score=0.0,
                passed=False,
                failures=["Vertex AI is not enabled or failed to initialize"],
                model_id=self._config.model_id,
                vertex_ai_enabled=self._config.enabled,
            )

        prompts = {
            "compliance": _COMPLIANCE_PROMPT.format(constitution=rubric or "", artifact=content),
            "artifact": _ARTIFACT_PROMPT.format(rubric=rubric or "", artifact=content),
            "harness": _HARNESS_PROMPT.format(rubric=rubric or "", content=content),
        }
        prompt = prompts.get(eval_type, prompts["artifact"])

        try:
            from vertexai.generative_models import GenerationConfig

            gen_config = GenerationConfig(
                max_output_tokens=self._config.max_output_tokens,
                temperature=self._config.temperature,
            )
            response = await model.generate_content_async(prompt, generation_config=gen_config)
            text = response.text.strip()

            import json
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
            result = json.loads(text)

            return EvaluateResponse(
                score=float(result.get("score", 0)),
                passed=bool(result.get("passed", False)),
                failures=result.get("failures", []),
                model_id=self._config.model_id,
                vertex_ai_enabled=True,
            )
        except Exception:
            logger.exception("Vertex AI evaluation failed")
            return EvaluateResponse(
                score=0.0,
                passed=False,
                failures=["Vertex AI call failed"],
                model_id=self._config.model_id,
                vertex_ai_enabled=True,
            )


_service: VertexAIService | None = None


def get_vertex_ai_service() -> VertexAIService:
    global _service
    if _service is None:
        from src.core.config import get_settings
        _service = VertexAIService(get_settings().vertex_ai)
    return _service
