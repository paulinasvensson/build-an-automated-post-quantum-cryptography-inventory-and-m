# Built a tool to automatically find every RSA/ECC usage in your codebase before quantum deadlines hit — feedback welcome

Hey all, security/compliance folks here. We've been building a tool that scans codebases, cert stores, and dependency chains to automatically inventory cryptographic usage (RSA, ECC, etc.) and maps out a prioritized migration path to NIST PQC algorithms.

Context: CNSA 2.0, NIST timelines, and DORA are pushing crypto-agility deadlines, but most teams are still doing this with consultants and spreadsheets. We wanted something like an SBOM scanner, but for crypto primitives instead of dependencies.

We're very early — this is a new product and we know it's not perfect yet. If you work in security/compliance at a regulated company (finance, defense, healthcare, infra), I'd genuinely love to hear: how are you currently tracking crypto debt? Would automated discovery actually move the needle for you, or is the real bottleneck elsewhere (budget, org buy-in, etc.)? Honest feedback appreciated.
