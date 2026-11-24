// Package importrules holds no code. Its tests read the import graph of the
// module and fail when a package imports what it must not.
//
// Several properties of sandmeter are properties of that graph, and nothing
// else would notice the one import that breaks them:
//
//   - policy and receipt are the two packages other programs may import, so
//     they depend on nothing internal;
//   - the root side links no code that parses what an agent or a model
//     wrote;
//   - the unprivileged client links no engine and no backend: what it cannot
//     link it cannot be tricked into running as the user;
//   - the lower layers (backends, layers, filters, proxy, images, differ) do
//     not know the engine, the service or the clients above them;
//   - the contract packages stay small enough to be read in one sitting.
//
// The rules are written as data in the test file, each with its reason.
package importrules
