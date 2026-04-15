"""RAG adapters package for vector DB backends — Cerberus AI suite."""

__all__ = [
	"vector_db_adapter",
	# embeddings
	"CUDAEmbeddingsProvider",
	"EmbeddingsConfig",
	"EmbeddingsProvider",
	"LocalDeterministicEmbeddingsProvider",
	"OpenAIEmbeddingsProvider",
	"get_embeddings_provider",
	# triplestore
	"CerebroRAMTripleStore",
	"get_global_triplestore",
	"set_global_triplestore",
	# ingestion
	"IngestionManager",
	"PathGuardIngestionManager",
	"get_ingestor",
	"shutdown_all",
	# metrics
	"MetricsCollector",
	"RetrievalFidelityTracker",
	"HardwareSaturationMonitor",
	"_RAGAuditWriter",
	"collector",
	"export_metrics",
	# chunking
	"chunk_text",
	"fingerprint_chunks",
	"logic_aware_chunk",
	# retriever
	"DenseRetriever",
	"SimpleBM25",
	"RetrieverCombiner",
	"Reranker",
	"CrossEncoderReranker",
	"RetrieverPipeline",
]
