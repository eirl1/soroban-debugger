# Session Summary

When a debug session concludes in the Soroban Debugger VS Code extension, a concise summary of the execution is presented.

## Overview

The Session Summary feature provides a quick recap of what happened during the debug session, eliminating the need to manually comb through console logs or output artifacts. This is especially useful for quickly checking the outcome of a contract invocation.

## What's Included

The summary appears in the Debug Console when the session terminates, detailing:

- **Final Status:** Whether the execution succeeded, failed, or panicked.
- **Budget Totals:** The total CPU instructions and Memory bytes consumed by the contract.
- **Event Count:** The number of events emitted during execution.
- **Storage Writes:** A count of the modifications made to the persistent storage.
- **Exported Artifact Paths:** Paths to any generated artifacts like storage snapshots or execution traces (if applicable).