"""The API inputs for proposals, change revisions and evidence retention."""

from pydantic import Field

from hst.assessment.models import StrictModel


class SaveProposal(StrictModel):
    finding_index: int = Field(ge=0)
    title: str = Field(min_length=1, max_length=200)
    change_id: str | None = None
    expected_revision: int = Field(default=0, ge=0)


class ReviseChange(StrictModel):
    title: str = Field(min_length=1, max_length=200)
    intents: list[dict] = Field(max_length=50)
    preconditions: list[dict] | None = Field(default=None, max_length=500)
    expected_revision: int = Field(ge=1)


class RetentionPolicy(StrictModel):
    reason: str = Field(min_length=1, max_length=500)
    release: bool = False
    retain_until: str | None = None
