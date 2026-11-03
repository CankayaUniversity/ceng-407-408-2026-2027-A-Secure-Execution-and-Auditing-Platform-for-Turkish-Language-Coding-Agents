"""Connect successful Gateway reads to persistent graph metadata and audit."""

from threading import RLock

from secure_agent.audit.logger import AuditLogger
from secure_agent.common.schemas import ReadFileToolCall, ToolResult
from secure_agent.provenance.constructor import ProvenanceGraphConstructor
from secure_agent.provenance.repository import ProvenanceRepository
from secure_agent.provenance.models import ExposureReceipt


class ProvenanceRecorder:
    """Serialize snapshot updates in one Gateway process.

    Delivery to the agent is not proven by an HTTP response being prepared;
    exposure is recorded separately after adapter acknowledgement.
    """

    def __init__(self, repository: ProvenanceRepository, audit_logger: AuditLogger):
        self.repository = repository
        self.audit_logger = audit_logger
        self._lock = RLock()

    def record_read(self, call: ReadFileToolCall, result: ToolResult) -> None:
        call = ReadFileToolCall.model_validate(call)
        result = ToolResult.model_validate(result)
        if result.request_id != call.request_id or result.status != "success":
            raise ValueError("A successful result matching the read request is required.")
        with self._lock:
            constructor = ProvenanceGraphConstructor()
            constructor.graph = self.repository.load_graph()
            source_id, result_id = constructor.record_read_result(
                result, source_path=call.arguments.path,
            )
            constructor.graph.nodes[result_id]["task_id"] = call.task_id
            self.repository.save_graph(constructor.get_graph())
            self.audit_logger.log_graph_event(call, source_id, result_id)

    def snapshot(self):
        with self._lock:
            return self.repository.load_graph()

    def record_exposure(self, receipt: ExposureReceipt) -> None:
        receipt = ExposureReceipt.model_validate(receipt)
        with self._lock:
            constructor = ProvenanceGraphConstructor()
            constructor.graph = self.repository.load_graph()
            node_id = f"result:{receipt.request_id}"
            source_id = f"source:{receipt.source_id}"
            graph = constructor.graph
            if (node_id not in graph or source_id not in graph
                    or graph.nodes[node_id].get("task_id") != receipt.task_id
                    or not graph.has_edge(node_id, source_id)
                    or graph.edges[node_id, source_id].get("edge_type") != "DERIVED_FROM"):
                raise ValueError("Receipt does not match the stored task read result.")
            agent_id = f"task:{receipt.task_id}"
            constructor.record_exposure(request_id=receipt.request_id, agent_id=agent_id)
            self.repository.save_graph(constructor.get_graph())
            self.audit_logger.log_source_exposure(receipt, agent_id)
