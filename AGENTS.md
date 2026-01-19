## CodeAgentAttack
This project evaluates the security of the code agents (specifically self-evolving code agents) under the RedCode benchmark (risky code execution and generation).

## Core Design Principles

### 1. Simple but Modular
- Emphasize modularity while avoiding unnecessary abstraction or over-engineering
- Eliminate code duplication and redundant validation checks, make sure to perform precise code editing

### 2. Refactoring Discipline
- Avoid partial or isolated refactoring
- Always consider related changes in the context of the overall design principles

### 3. Answer Style for Assistance
- Responses should be **accurate, precise, and to the point**
- Never combine multiple figures into a single PNG file, always save each figure separately when performing analysis

### 4. Finish first consider the feasibility, then perfect, avoid overkill or overcomplicated

## Project Structure
```
code-agent-attack/
├── DESIGN.md                    # Detailed experimental design
├── CLAUDE.md                    # This architecture guide
├── README.md                    # Project overview and RQs
│
├── external/                    # External dependencies
│   ├── mini-swe-agent/         # Base agent
│   ├── SWE-agent/         # Self-evolving agent
│   └── RedCode/                # Security benchmark
│
├── src/                         # Source code
│   ├── agents/                 # Agent wrappers
│   ├── attacks/                # Attack execution
│   ├── evolution/              # Evolution management
│   ├── evaluation/            # Evaluation orchestration
│   └── utils/                  # Utilities
│
├── data/                        # Data directory
│   ├── evolution_tasks/        # SWE-bench tasks for evolution
│   ├── redcode_samples/        # Selected RedCode test samples
│   └── results/                # Experimental results
│
├── notebooks/                   # Analysis notebooks
├── configs/                     # Configuration files
└── scripts/                     # Executable scripts