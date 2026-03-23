KLEE Symbolic Virtual Machine
=============================

[![Build Status](https://github.com/klee/klee/workflows/CI/badge.svg)](https://github.com/klee/klee/actions?query=workflow%3ACI)
[![Build Status](https://api.cirrus-ci.com/github/klee/klee.svg)](https://cirrus-ci.com/github/klee/klee)
[![Coverage](https://codecov.io/gh/klee/klee/branch/master/graph/badge.svg)](https://codecov.io/gh/klee/klee)

`KLEE` is a symbolic virtual machine built on top of the LLVM compiler
infrastructure. Currently, there are two primary components:

  1. The core symbolic virtual machine engine; this is responsible for
     executing LLVM bitcode modules with support for symbolic
     values. This is comprised of the code in lib/.

  2. A POSIX/Linux emulation layer oriented towards supporting uClibc,
     with additional support for making parts of the operating system
     environment symbolic.

Additionally, there is a simple library for replaying computed inputs
on native code (for closed programs). There is also a more complicated
infrastructure for replaying the inputs generated for the POSIX/Linux
emulation layer, which handles running native programs in an
environment that matches a computed test input, including setting up
files, pipes, environment variables, and passing command line
arguments.

For further information, see the [webpage](http://klee.github.io/).

## Kleener: Protocol-Aware Symbolic Execution

**Kleener** is a research extension of KLEE that adds protocol-aware symbolic execution capabilities for network protocols. It implements two types of monitors for protocol testing: requirement checking (RFC compliance validation) and recording monitors (differential symbolic execution). The framework currently supports DTLS (Datagram Transport Layer Security) and QUIC (Quick UDP Internet Connections) protocols.

> **Note**: This is a specialized research tool built on top of KLEE. For the standard KLEE symbolic execution engine, see the [main KLEE repository](https://github.com/klee/klee). Kleener periodically syncs with upstream KLEE to incorporate core improvements and bug fixes.

### Key Features

- **Protocol Parsers**: Parse network packets and expose protocol fields as structured data, simplifying monitor definition and enabling easy access to specific protocol fields
- **Socket Models**: Provides symbolic socket models for protocol-level testing
- **Two Types of Protocol Monitors**:
  - **Requirement Checking Monitors**: External components that observe protocol interactions, maintain state, and use symbolic execution to verify RFC compliance across a wide range of inputs without modifying the implementation under test
  - **Recording Monitors (Differential Symbolic Execution)**: Make protocol fields symbolic, record symbolic outputs from different implementations, and enable automated comparison to detect behavioral discrepancies and implementation-specific deviations
- **State Management**: Tracks protocol state machines and transitions during symbolic execution

### Monitor Types Explained

#### Requirement Checking Monitors
These monitors combine symbolic execution with runtime monitoring to test protocol implementations:
- Act as **external observers** of protocol interactions (no intrusive modifications to the implementation)
- Observe sequences of packets exchanged between protocol parties
- Maintain state information about the ongoing protocol interaction
- Use symbolic execution to generate a wide variety of symbolic inputs
- Explore all execution paths to verify RFC requirements are satisfied
- Detect and report requirement violations

This approach enables testing stateful network protocols against their specifications across many possible inputs, including those that could be supplied by an attacker. Unlike traditional runtime verification that checks concrete executions, these monitors leverage symbolic execution to systematically explore the implementation's behavior under symbolic inputs.

**Example: DTLS Sequence Number Window Monitor** (see [record-sequence-number.c](runtime/Intrinsic/Protocols/DTLS/monitors/record-sequence-number.c))

The DTLS RFC 6347 requires implementations to reject duplicate records using a sliding receive window (typically 64 records). The monitor:
- Observes the sequence of DTLS records exchanged between parties
- Maintains state: tracks received sequence numbers and the "right edge" (highest validated sequence number)
- Makes sequence numbers symbolic to explore various scenarios
- Encodes the RFC requirement: records outside the valid window must be rejected
- Tests with symbolic inputs that violate the window requirement
- Detects if the implementation incorrectly accepts invalid sequence numbers

#### Recording Monitors (Differential Symbolic Execution)
These monitors enable differential testing of protocol implementations:
- **Make protocol fields symbolic**: Specific fields in protocol messages (from either party) are made symbolic
- **Implementation processes symbolic inputs**: The implementation under test processes these symbolic inputs and generates responses
- **Record symbolic outputs**: The monitor records the symbolic values in the response using `klee_print_expr`
- **Cross-implementation comparison**: By running the same monitor on different implementations, their symbolic outputs can be compared
- **Detect behavioral discrepancies**: Differences in symbolic outputs reveal inconsistencies between implementations, which may indicate bugs, vulnerabilities, or specification ambiguities

This technique systematically explores how different implementations respond to the same symbolic inputs, enabling automated discovery of implementation-specific behaviors and deviations from expected protocol semantics.

**Example: DTLS Epoch Differential Monitor** (see [epoch-diff-testing.c](runtime/Intrinsic/Protocols/DTLS/monitors/diff-testing/epoch-diff-testing.c))

The epoch field differential monitor makes the DTLS epoch field symbolic in a client message. Each tested implementation (e.g., OpenSSL, GnuTLS, wolfSSL) processes this symbolic input and generates responses. The monitor records each implementation's symbolic output (response record fields). Comparing these outputs reveals if implementations handle epoch values differently, potentially exposing security vulnerabilities or interoperability issues.

### Key Components and Locations

#### DTLS Protocol Support
- **Headers**: `include/klee/Protocols/dtls/`
  - `dtls_records.h` - DTLS record layer structures and parsers
  - `dtls_states.h` - Protocol state machine definitions
  - `dtls_socket_model.h` - Socket model interface
  - `dtls_monitors.h` - Monitor function declarations

- **Implementation**: `runtime/Intrinsic/Protocols/DTLS/`
  - `dtls_records.c` - Record parsing and handling
  - `dtls_states.c` - State machine implementation
  - `dtls_socket_model.c` - Socket operations

- **Monitors**: `runtime/Intrinsic/Protocols/DTLS/monitors/`
  - Requirement checking monitors (epoch, content-type, record-version, etc.)
  - Fragmentation and reassembly monitors
  - Handshake validation monitors
  
- **Recording Monitors (Differential Symbolic Execution)**: `runtime/Intrinsic/Protocols/DTLS/monitors/diff-testing/`
  - `content-type-diff-testing.c`
  - `epoch-diff-testing.c`
  - `handshake-type-diff-testing.c`
  - `message-sequence-number-diff-testing.c`
  - `record-sequence-number-diff-testing.c`
  - `record-version-diff-testing.c`

#### QUIC Protocol Support
- **Headers**: `include/klee/Protocols/quic/`
  - `quic_packets.h` - QUIC packet structures
  - `quic_states.h` - Protocol state definitions
  - `quic_socket_model.h` - Socket model interface
  - `quic_monitors.h` - Monitor declarations

- **Implementation**: `runtime/Intrinsic/Protocols/QUIC/`
  - `quic_packets.c` - Packet parsing
  - `quic_states.c` - State management
  - `quic_socket_model.c` - Socket operations

- **Monitors**: `runtime/Intrinsic/Protocols/QUIC/monitors/`
  - Requirement checking monitors (frame-type, packet-length, version-negotiation, etc.)
  - Note: Recording monitors for differential symbolic execution are not yet implemented for QUIC

#### Shared Protocol Infrastructure
- **Headers**: `include/klee/Support/Protocols/`
  - `datagram.h` - Generic datagram handling
  - `helper.h` - Common protocol utilities

- **Implementation**: `runtime/Intrinsic/Protocols/`
  - `datagram.c` - Datagram operations
  - `helper.c` - Helper functions


### Usage

#### Selecting a Monitor

Monitors are selected at runtime using environment variables:

1. **Set the experiment ID**: Each monitor has a unique experiment ID defined in the protocol's monitor header (e.g., [dtls_monitors.h](include/klee/Protocols/dtls/dtls_monitors.h)):
   - Requirement checking monitors: `epoch_requirement 24`, `record_sequence_requirement 26`, etc.
   - Recording monitors: `epoch_diff_test 102`, `content_type_diff_test 100`, etc.

2. **Configure execution parameters**:
   ```bash
   export KLEE_SYMBOLIC_EXPERIMENT=102  # Select monitor by experiment ID (e.g., epoch_diff_test)
   export STATE_TO_CHECK="server"        # Which side to monitor: "server" or "client"
   export CHOSEN_CIPHER="psk"            # Cipher suite: "psk" or "ecc"
   export IS_FRAGMENTED="no"             # Fragmentation: "yes" or "no"
   ```

3. **Run KLEE**: When the protocol implementation is executed under KLEE, the `set_monitor_handle()` function uses the experiment ID to select the appropriate monitor function from its internal table, and the monitor is invoked during protocol execution.

#### Workflow for Requirement Checking

1. Select a requirement checking monitor experiment ID (e.g., `record_sequence_requirement 26`)
2. Configure environment variables as described above
3. Run KLEE with the protocol implementation under test
4. KLEE symbolically explores the implementation's behavior with symbolic inputs
5. Monitor detects and reports RFC violations or protocol compliance issues
6. Analyze reported violations to identify bugs or security vulnerabilities

#### Workflow for Differential Testing

1. Select a recording monitor experiment ID (e.g., `epoch_diff_test 102`)
2. Configure environment variables and run KLEE on the first implementation
3. Repeat step 2 for each additional implementation under test
4. Collect the symbolic outputs recorded by `klee_print_expr` (stored in `test*.resp` files in the KLEE output directory, typically `klee-out-<N>/`)
5. Perform offline differential analysis using an SMT solver (e.g., Z3): For each pair of implementations with path conditions PC and PC' and outputs o and o', check if PC ∧ PC' ∧ (o ≠ o') is satisfiable
6. If satisfiable, a behavioral discrepancy exists where both implementations can reach their respective states but produce different outputs
7. Analyze discovered discrepancies to determine if they indicate bugs, vulnerabilities, or specification ambiguities

Currently, DTLS supports both monitor types, while QUIC only supports requirement checking monitors.

## Publications

For more details on the requirement checking monitor approach, see:

**Hooman Asadian, Paul Fiterău-Broştean, Bengt Jonsson, and Konstantinos Sagonas.** 2024. Monitor-based Testing of Network Protocol Implementations Using Symbolic Execution. In *Proceedings of the 19th International Conference on Availability, Reliability and Security (ARES '24)*. Article 17, 1-12. DOI: [10.1145/3664476.3664521](https://doi.org/10.1145/3664476.3664521)

## Development Guide

### Adding New Monitors

Protocol monitors follow a consistent structure. There are two types:

1. **Requirement Checking Monitors**: Validate RFC compliance
2. **Recording Monitors**: Enable differential symbolic execution

#### 1. Create Monitor Implementation

Create a new `.c` file in the appropriate monitors directory:
- Requirement checking: `runtime/Intrinsic/Protocols/DTLS/monitors/` or `runtime/Intrinsic/Protocols/QUIC/monitors/`
- Recording monitors: `runtime/Intrinsic/Protocols/DTLS/monitors/diff-testing/`

**Requirement Checking Monitor Structure:**

Monitors are external components that observe protocol interactions. They maintain state and use symbolic execution to verify requirements.

```c
#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/klee.h"
#include <assert.h>

#define INITIAL 0
#define DONE 1

static STATE local_state = INITIAL;

void your_requirement_monitor_server(RECORD *P, bool is_record_client_generated)
{
    if (is_record_client_generated && local_state == INITIAL) 
    {
        // Make field symbolic to explore all possible values
        kleener_make_symbolic(&P->field, sizeof(P->field), "field_value");
        
        // Encode the RFC requirement using klee_assume
        // Assume the field has an INVALID value to test rejection
        klee_assume(P->field > MAX_VALID_VALUE);
        
        local_state = DONE;
    }
    else if (!is_record_client_generated && local_state == DONE)
    {
        // Check if implementation violated requirement
        // If response is not an error, the implementation accepted invalid input
        if (P->content_type != Alert_REC)
            assert(0 && "RFC requirement violated: invalid field accepted");
    }
}
```

**Recording Monitor Structure (for differential symbolic execution):**
```c
#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/klee.h"
#include <assert.h>

#define INITIAL 0
#define RECORD_RECEIVED 1
#define EXIT 2

static STATE local_state = INITIAL;

void your_recording_monitor_server(RECORD *P, bool is_record_client_generated)
{
    if (is_record_client_generated && local_state == INITIAL) 
    {
        // Make the target field symbolic - can be in client or server messages
        // depending on what protocol behavior you want to test
        kleener_make_symbolic(&P->field, sizeof(P->field), "field_name");
        local_state = RECORD_RECEIVED;
    }
    else if (!is_record_client_generated && local_state == RECORD_RECEIVED) 
    {
        // Record the symbolic output from the response
        // This captures how the implementation responded to symbolic input
        generate_dtls_output(P);  // Records symbolic values via klee_print_expr
        
        local_state = EXIT;
    }
    else if (local_state == EXIT)
    {
        return;
    }
}
```

The `generate_dtls_output()` function uses `klee_print_expr()` to record symbolic values from the response, enabling comparison across different implementations run with the same symbolic inputs. These outputs are written to `test*.resp` files in the KLEE output directory.

#### 2. Declare Monitor Functions

Add function declarations to the appropriate header:
- DTLS: `include/klee/Protocols/dtls/dtls_monitors.h`
- QUIC: `include/klee/Protocols/quic/quic_monitors.h`

#### 3. Register Monitor

In the monitor header file, add:
- A unique experiment ID constant (e.g., `#define your_requirement 84`)
- Entry in the monitor table within `set_monitor_handle()` function

#### 4. Add to Build System

Add your monitor file to `runtime/Intrinsic/CMakeLists.txt` in the `SRC_FILES` list:
```cmake
# For requirement checking monitors:
Protocols/DTLS/monitors/your-monitor.c

# For recording monitors (differential symbolic execution):
Protocols/DTLS/monitors/diff-testing/your-monitor-diff-testing.c
```

### Extending to QUIC Differential Symbolic Execution

To add recording monitors for QUIC (enabling differential symbolic execution):

#### 1. Create Directory
```bash
mkdir -p runtime/Intrinsic/Protocols/QUIC/monitors/diff-testing
```

#### 2. Identify Target Fields

Review QUIC packet structures in `include/klee/Protocols/quic/quic_packets.h` and identify fields for differential symbolic execution (e.g., packet number, connection ID, frame types).

#### 3. Implement Recording Monitors

Follow the DTLS recording monitor pattern:
- Make target field symbolic when first received from client
- Capture and report the symbolic value in server's response using `generate_quic_output()` (needs implementation)
- Use state machine pattern to manage monitor lifecycle

Example:
```c
void field_name_diff_testing_server(QUIC_PACKET *P, bool is_packet_client_generated)
{
    if (is_packet_client_generated && local_state == INITIAL) {
        kleener_make_symbolic(&P->field, sizeof(P->field), "field_name");
        local_state = PACKET_RECEIVED;
    }
    else if (!is_packet_client_generated && local_state == PACKET_RECEIVED) {
        generate_quic_output(P);  // Implement this function
        local_state = EXIT;
    }
}
```

#### 4. Add Monitor Constants

In `include/klee/Protocols/quic/quic_monitors.h`, define recording monitor experiment IDs:
```c
/* Recording Monitors for Differential Symbolic Execution */
#define field_name_diff_test 200
#define another_field_diff_test 202
// etc.
```

#### 5. Register in Build System

Add all new recording monitors to `runtime/Intrinsic/CMakeLists.txt`.

#### 6. Implement Output Capture

Create `generate_quic_output()` function in QUIC implementation to capture and report symbolic outputs for differential symbolic execution comparison. This function should use `klee_print_expr()` to record symbolic values from QUIC packet responses, similar to how `generate_dtls_output()` works for DTLS.

### Adding New Protocols

To add support for a new protocol (e.g., TLS 1.3):

#### 1. Create Protocol Directory Structure
```
include/klee/Protocols/protocol_name/
  - protocol_packets.h    # Packet/message structures
  - protocol_states.h     # State machine definitions
  - protocol_socket_model.h  # Socket operations
  - protocol_monitors.h   # Monitor declarations

runtime/Intrinsic/Protocols/PROTOCOL_NAME/
  - protocol_packets.c    # Parsing implementation
  - protocol_states.c     # State management
  - protocol_socket_model.c  # Socket operations
  - monitors/
    - protocol_monitors.c  # Monitor registry
    - [individual monitor files]
```

#### 2. Define Protocol Structures

In `protocol_packets.h`, define:
- Message/packet structures following RFC specifications
- Parsing functions for protocol messages
- Protocol-specific constants and enums

#### 3. Implement Parser

In `protocol_packets.c`:
- Implement parsing functions to extract fields from raw bytes
- Handle protocol-specific encoding (e.g., variable-length fields, compression)
- Follow the pattern used in `dtls_records.c` or `quic_packets.c`

#### 4. Create State Machine

In `protocol_states.h` and `protocol_states.c`:
- Define protocol states as enums (e.g., `CH0_RECVD`, `SH_RECVD`, `CFI_RECVD` for DTLS handshake stages)
- Implement state transition logic
- Track connection state throughout symbolic execution

The state machine is crucial because:
- **Monitors are state-aware**: Each monitor specifies which protocol states it applies to (via `set_monitor_valid_states()`)
- **Environment variable `STATE_TO_CHECK`** selects which protocol state to symbolically execute
- **Targeted testing**: Enables focusing symbolic execution on specific protocol phases (e.g., test epoch handling only during encrypted handshake)

Without state tracking, you cannot selectively activate monitors at the right protocol phase or test state-dependent behaviors.

#### 5. Implement Socket Model

In `protocol_socket_model.c`:
- Intercept socket operations (e.g., `recvfrom`, `sendto`) from the protocol implementation
- Manage symbolic packet queues for client/server communication
- Invoke monitors at appropriate points during packet exchange
- Initialize monitor handles and execution parameters from environment variables

The socket model is essential because it enables testing unmodified protocol implementations by intercepting their network I/O. When the implementation calls socket functions, your socket model:
- Delivers symbolic packets from the queue (instead of real network I/O)
- Calls monitors before/after processing each packet
- Handles protocol-specific I/O patterns

Follow the pattern used in [dtls_socket_model.c](runtime/Intrinsic/Protocols/DTLS/dtls_socket_model.c) or [quic_socket_model.c](runtime/Intrinsic/Protocols/QUIC/quic_socket_model.c).

#### 6. Create Monitors

Develop both types of monitors based on RFC requirements:
- **Requirement checking monitors**: Extract and validate key requirements from protocol specifications
- **Recording monitors**: Identify fields for differential symbolic execution to compare implementations
- Follow the monitor structure patterns described above

#### 7. Build Configuration

Update `runtime/Intrinsic/CMakeLists.txt` to include all new source files in the `SRC_FILES` list.

#### 8. Testing

Create test cases in `test/` directory to validate:
- Parser correctness
- Monitor detection capabilities
- State machine behavior
- Integration with KLEE execution

> **Note**: Core KLEE modifications (SpecialFunctionHandler.cpp, Executor.cpp) should not be needed for new protocols, as the protocol monitoring framework is already integrated. Only modify KLEE core if introducing entirely new special functions or execution semantics not covered by the existing framework.
