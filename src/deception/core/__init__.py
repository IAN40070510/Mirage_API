"""H：依 D 契約組合 C 的明確指令與 E 資料，輸出待 I 驗證的候選。"""

from .composer import CompositionError, ResponseComposer
from .handoff import verify_candidate
from .models import CandidateIdentity, CandidateResponse, CompositionPlan, DataBinding

__all__ = ["CompositionError", "ResponseComposer", "CandidateIdentity", "CandidateResponse",
           "CompositionPlan", "DataBinding", "verify_candidate"]
