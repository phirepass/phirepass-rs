use tokio::runtime::{Builder, Runtime};

pub struct RuntimeBuilder {
    inner: Builder,
}

impl RuntimeBuilder {
    pub fn create() -> Self {
        let flavor = std::env::var("TOKIO_FLAVOR").unwrap_or_else(|_| "multi_thread".to_string());

        let worker_threads: Option<usize> = std::env::var("TOKIO_WORKER_THREADS")
            .ok()
            .and_then(|v| v.parse().ok());

        let max_blocking_threads: usize = std::env::var("TOKIO_MAX_BLOCKING_THREADS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(32);

        let mut builder = match flavor.as_str() {
            "current_thread" => Builder::new_current_thread(),
            "multi_thread" | "multi" | "" => Builder::new_multi_thread(),
            other => {
                eprintln!("Invalid TOKIO_FLAVOR={other:?}; using multi_thread");
                Builder::new_multi_thread()
            }
        };

        if flavor != "current_thread"
            && let Some(worker_threads) = worker_threads
        {
            builder.worker_threads(worker_threads);
        }

        builder
            .max_blocking_threads(max_blocking_threads)
            .enable_all();

        Self { inner: builder }
    }

    pub fn with_worker_threads(mut self, worker_threads: usize) -> Self {
        self.inner.worker_threads(worker_threads);
        self
    }

    pub fn build(mut self) -> std::io::Result<Runtime> {
        self.inner.build()
    }
}
