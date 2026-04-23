# Resource Timeline

The Resource Timeline feature provides sequential tracking of CPU instructions and Memory allocations over a contract execution run. This allows operators to answer "Where did the resource spike happen?" without manually stepping the exact bounds through trial and error.

## Usage
The timeline tracks discrete checkpoints when hooks enter or exit calls. All data aggregates sequentially and includes delta metrics (+CPU / +Mem) relative to the prior checkpoint.
This is fully readable in both the command line output and generated profile artifacts.
