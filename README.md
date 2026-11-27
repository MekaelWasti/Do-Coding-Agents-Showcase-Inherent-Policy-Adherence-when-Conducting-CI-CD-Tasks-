# Do Coding Agents Showcase Inherent Policy Adherence when Conducting CI-CD Tasks? An Agentic-PR based-Explorative Study

Research code for analyzing security and correctness changes in agent-attributed GitHub Actions workflow edits. The current pipeline workflow files before and after agent-associated PRs are analyzed using static analysis tools such as zizmor, actionlint, custom rule scripts, and relative change checks. We empirically study the results to gauge how well agents follow CI/CD best practices and conventions, and examine what may be influencing their decisions not to.

## Code

- [Research Question 1: Analyzing Static Analyses on Agent-Associated PRs](Experiments/RQ1.ipynb)
- [Research Question 2: File-Associative Analysis on Agent-Edit Behaviour](Experiments/RQ2_3.ipynb) (Cells 1-29)
- [Research Question 3: Categorical Analysis on Agent-Edit Behaviour](Experiments/RQ2_3.ipynb) (Cells 30-40)

## Dataset

We use the [AIDev v5 dataset](https://huggingface.co/datasets/hao-li/AIDev), which holds 7.6M agent-associated PRs with a cutoff date of March 31st, 2026. The included "pop" subset filters for PRs originating from GitHub repositories with more than 100 stars. Our data tables created from the dataset through static tool analyses are available [here](Data/) 
