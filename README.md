# AI-Driven Firewall Prototype

This project implements a backend prototype for an AI-driven firewall, designed to analyze network connections, apply security policies, and integrate AI-based anomaly detection to determine real-time security actions.

## Table of Contents

* [How to Run the Code](#how-to-run-the-code)
* [Architectural Design and Key Decisions](#architectural-design-and-key-decisions)
* [Core Logic Highlights](#core-logic-highlights)
    * [AI Anomaly Scoring and Caching for Existing Connections](#ai-anomaly-scoring-and-caching-for-existing-connections)
    * [Asynchronous Batching for AI Service Calls](#asynchronous-batching-for-ai-service-calls)
    * [Fast Policy Retrieval with Indexed Policies](#fast-policy-retrieval-with-indexed-policies)
* [Known Limitations](#known-limitations)
* [Future Thoughts](#future-thoughts)
* [Tests](#tests)
* [Example API Requests](#example-api-requests)

---

## How to Run the Code

To run this prototype locally, follow these steps:

**Clone the repository:**
    [https://github.com/nogahn/firewall-analyzer.git](https://github.com/nogahn/firewall-analyzer.git)


### Without Docker:
1.  **Create a virtual environment (recommended):**
    ```bash
    cd firewall-analyzer
    python -m venv venv
    source venv/bin/activate # On Windows: .\venv\Scripts\activate
    ```
2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **Run the application locally:**
    ```bash
    uvicorn main:app --reload
    ```
    The API will be available at `http://127.0.0.1:8000`.


### Running with Docker:

Alternatively, you can run the application using Docker. Ensure you have Docker installed and running.

1.  **Build the Docker Image:**
    Build the Docker image, tagging it as `firewall-app`.

    ```bash
    docker build -t firewall-app .
    ```

2.  **Run the Docker Container:**
    Run the container, mapping port 8000 inside to port 8000 on your host machine.

    ```bash
    docker run -d -p 8000:8000 --name my-firewall-app firewall-app
    ```

---

## Architectural Design and Key Decisions

The prototype is built using FastAPI, offering a modern, asynchronous web framework ideal for high-performance APIs.

Key architectural decisions include:

* **Modular Design:** The application is separated into distinct concerns:
    * `main.py`: FastAPI application setup, API endpoints, dependency injection.
    * `src/core/models.py`: Pydantic models for data validation and serialization.
    * `src/services/ai_mock_service.py`: Simulates an external AI service for anomaly scoring.
    * `src/services/ai_service_client.py`: Manages communication with the AI service, implementing crucial batching and rate-limiting.
    * `src/services/policy_manager.py`: Stores and efficiently retrieves security policies.
    * `src/services/decision_engine.py`: Orchestrates the connection evaluation process, combining policy matching and AI anomaly scoring.
    * `config.py`: Centralized configuration for various service parameters.
* **Robust Input Validation with Pydantic Models:** All incoming API request bodies (e.g., `ConnectionInput`, `Policy`) are defined using **Pydantic models**. This provides automatic and robust data validation, ensuring that:
    * Data types are correct (e.g., `source_ip` is a valid IP address, `destination_port` is an integer within the valid port range).
    * Required fields are present.
    * Custom validations (like ensuring `protocol` is uppercase or `policy_id` matches a pattern) are enforced using `@field_validator`.
    This approach prevents malformed or malicious input from reaching the core logic, improving the reliability and security of the service.
* **Asynchronous Concurrency with `asyncio`:** The entire application leverages Python's `asyncio` framework. This allows for efficient handling of concurrent network requests and I/O operations (like communicating with the AI service) without blocking the main event loop. This non-blocking nature is crucial for achieving high throughput and responsiveness, especially under simulated heavy traffic, enabling the system to manage many connections simultaneously.
* **In-Memory Storage:** For simplicity and to meet the prototype's scope, all operational data, including defined security policies and the results of analyzed connections, are stored in memory. This demonstrates the core logic without the overhead of a persistent database, suitable for a functional prototype.
* **Externalized Configuration:** Key operational parameters, such as API rate limits, AI service mock settings (processing time, error rate, batching parameters), and logging levels, are centralized in `config.py`. This design choice allows for easy adjustment and tuning of the system's behavior without modifying the core application logic, facilitating deployment and maintenance.
* **Rate Limiting:** `fastapi-limiter` is integrated using Redis (or `fakeredis` for local development) to control the incoming request rate to the `/connections` endpoint, preventing abuse and ensuring stability under load.
* **Graceful Shutdown:** The `lifespan` event handler in FastAPI ensures that the `AIServiceClient` is properly started and stopped, processing any pending AI requests before the application fully shuts down.

---

## Core Logic Highlights

### AI Anomaly Scoring and Caching for Existing Connections

The `DecisionEngine` incorporates a mechanism to optimize AI anomaly scoring for connections that share key characteristics.

* **Caching Strategy:** When a new connection arrives, a unique `cache_key` is generated using a hash of `source_ip`, `destination_ip`, `destination_port`, and `protocol`.
* **Score Reuse:** Before sending a connection to the AI service, the `DecisionEngine` checks if an anomaly score for the exact same connection "signature" (defined by the `cache_key`) has been previously obtained and cached in `_cache_key_to_anomaly_score`.
* **Efficiency Gain:** If a score exists in the cache, it's immediately returned, avoiding redundant calls to the (potentially slow and rate-limited) AI service. This significantly improves performance for repeated connection patterns. If no score is found, the connection is submitted for AI analysis, and its score is then cached for future use.

### Asynchronous Batching for AI Service Calls

To address the AI service's rate limit of 100 requests/sec while supporting system peaks up to 1000 requests/sec, an asynchronous batching mechanism is implemented in `AIServiceClient`.

* **Request Queue:** Incoming connection anomaly scoring requests are placed into an `asyncio.Queue` (`pending_queue`).
* **Background Processing Task:** A dedicated background `_process_batches` task runs continuously:
    1.  It `_collect_batch` of connections from the `pending_queue`, either when `max_batch_size` (e.g., 10 connections) is reached or after a `batch_timeout` (e.g., 50ms) elapses, whichever comes first. This ensures efficient bundling of requests.
    2.  It then calls `_send_batch_to_ai`, which applies a `min_interval` wait (calculated from `AI_RATE_LIMIT_RPS`) to ensure that the actual calls to the `AIMockService` respect the simulated AI service's rate limit.
* **Future Objects:** Each individual `get_anomaly_score` call returns an `asyncio.Future` object. When the batch processing completes and a score is obtained for that specific connection, the `Future` is resolved with the result. This allows individual API calls to await their specific AI score without blocking the entire system.
* **Graceful Degradation:** This batching and rate-limiting approach acts as a buffer, smoothing out traffic spikes to the AI service and preventing it from being overwhelmed, thereby contributing to graceful degradation under heavy load.

### Fast Policy Retrieval with Indexed Policies

The `PolicyManager` employs an indexing mechanism to quickly find matching security policies, rather than iterating through all policies for every connection.

* **Indexed Policies:** When a policy is added via `add_policy`, its conditions (e.g., `destination_port`, `source_ip`) are indexed. For each field value (e.g., `destination_port: 443`), a `Set` of `_original_order` indices of policies that contain that specific condition is stored in `_indexes`.
* **Efficient Candidate Generation:** In `get_matching_policy`, instead of checking every policy, the system first gathers all policies that match *any* of the connection's attributes based on the pre-built indexes. For instance, if a connection has `destination_port: 443`, it retrieves all policies indexed for port 443.
* **Set Intersection/Union:** The `candidate_sets` are used to find policies that share common attributes. For conditions, the code performs a `set.union` of all potential matching policy orders.
* **Prioritized Evaluation:** Finally, it iterates through these candidate policies in their `_original_order` (insertion order) and performs a full `_evaluate_policy_conditions` check only on these much smaller subset of policies. This significantly reduces the number of full condition evaluations required for each connection. While a precise Big O notation depends on data distribution, this approach transforms the lookup from a worst-case **O(N)** (where N is the total number of policies, if all policies were checked) to an average case where only a small subset of relevant policies are fully evaluated, making policy lookup highly efficient.
* **Policies Without Conditions:** Policies without any conditions are explicitly tracked in `_policies_without_conditions` and are always included as candidates, ensuring they are considered based on their insertion order.

---

## Known Limitations

* **In-Memory Storage:** All data (connections, policies) is stored in memory. A production system would require a persistent database (e.g., PostgreSQL, MongoDB) or a distributed cache (e.g., Redis for connection details).
* **Policy Complexity:** Currently, only "==" (equality) operator is supported for policy conditions. Expanding this to include other operators (e.g., `>`, `<`, `contains`, `CIDR range`) would enhance policy expressiveness.
* **No Policy Deletion/Modification:** Policies can only be added, not updated or deleted. A full API would need `PUT` or `DELETE` endpoints for policies.
* **AI Mock Service:** The AI anomaly scoring is simulated. In a real-world scenario, this would involve integrating with an actual machine learning model or external AI service.
* **Error Handling and Retries:** While basic exception handling is present, a more robust system would implement sophisticated retry mechanisms with backoff strategies for external service calls (like AI service).
* **Monitoring and Observability:** No dedicated metrics, tracing, or advanced logging are implemented. Integrating with Prometheus, Grafana, or OpenTelemetry would be crucial for production.
* **Security:** This is a prototype and does not include authentication, authorization, or detailed input sanitization beyond Pydantic's basic validation.
* **Scaling Redis:** For the `fastapi-limiter`, using a single Redis instance might become a bottleneck at extremely high loads. A Redis cluster or other distributed rate-limiting solutions could be considered.
* **Advanced Policy Matching:** For extremely complex policy sets, more advanced indexing structures or a rule engine might be beneficial.

---

### Future Thoughts

This prototype lays a solid foundation for an AI-driven firewall. With more time and resources, the following areas would be key for further development and production readiness:

* **Persistent Data Storage:** Transition all in-memory data (policies, analyzed connections) to a robust, persistent database (e.g., PostgreSQL, MongoDB) or a distributed cache for durability and scalability.

* **Advanced Policy Engine:** Enhance policy conditions to support more operators (e.g., `>`, `<`, `contains`), logical combinations (`AND`, `OR`), and time-based rules for greater expressiveness.

* **Real AI/ML Integration:** Replace the mock AI service with an actual external machine learning model or specialized LLM for more sophisticated anomaly detection, handling real API calls and authentication securely.

* **Distributed Batching and AI Service Coordination (Maintaining Synchronous API Feel):** For multi-instance deployments, implement a centralized message queue (e.g., Kafka, Redis Streams) for AI requests with correlation IDs. Dedicated workers would process these requests in optimal batches, enforce global rate limits, and publish results back to a response channel. The API instance would await an `asyncio.Future` linked to its correlation ID, preserving the synchronous interaction from the client's perspective while leveraging distributed processing.

* **Enhanced Scalability & High Availability:** Utilize containerization (Docker) and orchestration (Kubernetes) for easier scaling and management. Implement distributed caching (e.g., Redis) for anomaly scores across instances.

* **Comprehensive Observability:** Integrate metrics (Prometheus/Grafana), structured logging (centralized system), and distributed tracing (OpenTelemetry) for better monitoring and debugging.

* **Authentication & Authorization:** Implement robust user authentication and role-based access control (RBAC) for API endpoints, especially for policy management.

* **Web User Interface (UI):** Develop a simple UI for managing policies and monitoring connection decisions and alerts.

* **Alerting & Reporting:** Integrate with external alerting systems (e.g., PagerDuty, Slack) and generate security reports.

---

## Tests

The project includes a comprehensive suite of unit and integration tests, written using `pytest`, to ensure the correctness and robustness of the various components. These tests cover individual service logic, inter-service communication, and API endpoint behavior.

To run all tests, navigate to the project's root directory and execute:
```
pytest
```
Here's a breakdown of the test files and their coverage:

* **`test_ai_mock_service.py`**:
    * **Purpose:** Verifies the functionality of the simulated AI anomaly scoring service.
    * **Coverage:** Tests initialization, basic anomaly score generation for a batch of connections, handling of empty connection lists, and the simulation of service errors.
* **`test_ai_service.py`**:
    * **Purpose:** Validates the `AIServiceClient`, which manages interactions with the AI service, including batching and rate limiting.
    * **Coverage:** Ensures the client properly starts and stops its background processing task, handles graceful shutdown (processing remaining items), manages errors during AI calls, and correctly implements batching and rate-limiting to meet throughput requirements. It also includes a test for estimated throughput under load.
* **`test_decision_engine.py`**:
    * **Purpose:** Confirms the core decision-making logic, combining policy evaluation and AI anomaly scoring.
    * **Coverage:** Tests the anomaly score caching mechanism (ensuring scores are reused for identical connections), default decision logic when no policies match (based on anomaly score thresholds), and how policy matches override or influence decisions. It also verifies the retrieval of analyzed connection details.
* **`test_main.py`**:
    * **Purpose:** Provides integration tests for the FastAPI application's API endpoints.
    * **Coverage:** Tests successful submission of connection data (`POST /connections`), defining security policies (`POST /policies`), retrieving connection details (`GET /connections/{id}`), and handling of duplicate policy IDs. Crucially, it includes extensive parametrization for invalid inputs to both `/connections` and `/policies` endpoints, ensuring robust validation and error responses (HTTP 422).
* **`test_policey_manager.py`**:
    * **Purpose:** Verifies the `PolicyManager`'s ability to store and efficiently retrieve security policies.
    * **Coverage:** Tests adding policies, the logic for finding the *first* matching policy based on insertion order and conditions, handling of multiple conditions (all must match), and the special case of policies without conditions. It also includes tests for scenarios where no policies match or where policies conflict, and ensures that adding duplicate policy IDs raises an error.
---

## Example API Requests

You can use `curl` or Postman to test the API endpoints.

### 1. Define Security Policy (`POST /policies`)

```bash
curl -X POST "http://127.0.0.1:8000/policies" \
-H "Content-Type: application/json" \
-d '{
  "policy_id": "P-001",
  "conditions": [
    { "field": "destination_port", "operator": "==", "value": 80 },
    { "field": "protocol", "operator": "==", "value": "TCP" }
  ],
  "action": "block"
}'
```


```bash
curl -X POST "http://127.0.0.1:8000/policies" \
-H "Content-Type: application/json" \
-d '{
  "policy_id": "P-002",
  "conditions": [
    { "field": "source_ip", "operator": "==", "value": "192.168.1.10" }
  ],
  "action": "alert"
}'
```


```bash
curl -X POST "http://127.0.0.1:8000/policies" \
-H "Content-Type: application/json" \
-d '{
  "policy_id": "P-003",
  "conditions": [],
  "action": "allow"
}'
```

### 2. Submit Network Connection Data (POST /connections)

```bash
curl -X POST "http://127.0.0.1:8000/connections" \
-H "Content-Type: application/json" \
-d '{
  "source_ip": "192.168.1.10",
  "destination_ip": "10.0.0.5",
  "destination_port": 443,
  "protocol": "TCP",
  "timestamp": "2025-04-30T12:34:56Z"
}'
```

```bash
curl -X POST "http://127.0.0.1:8000/connections" \
-H "Content-Type: application/json" \
-d '{
  "source_ip": "192.168.1.10",
  "destination_ip": "10.0.0.5",
  "destination_port": 443,
  "protocol": "TCP",
  "timestamp": "2025-04-30T12:34:56Z"
}'
```
```bash
curl -X POST "http://127.0.0.1:8000/connections" \
-H "Content-Type: application/json" \
-d '{
  "source_ip": "192.168.1.1",
  "destination_ip": "8.8.8.8",
  "destination_port": 53,
  "protocol": "UDP",
  "timestamp": "2025-04-30T12:35:00Z"
}'
```
### 3. Retrieve Connection Decision Details (GET /connections/{id})
(Replace {uuid} with an actual connection_id returned from a POST /connections request.)

```bash
curl -X GET "http://127.0.0.1:8000/connections/YOUR_CONNECTION_ID_HERE"
```

### Explanation of Examples

* **Define Security Policy (`POST /policies`)**: These examples illustrate adding various policies: one blocking specific ports/protocols (`P-001`), another alerting on a source IP (`P-002`), and a default "allow" policy (`P-003`). Policies are evaluated in their submission order.

* **Submit Network Connection Data (`POST /connections`)**: These commands submit connection details for evaluation. Responses show the `DecisionEngine`'s outcome based on policies and the AI anomaly score, demonstrating policy matching and score caching.

* **Retrieve Connection Decision Details (`GET /connections/{id}`)**: This shows how to retrieve the full analysis and decision for a previously submitted connection using its unique ID.
