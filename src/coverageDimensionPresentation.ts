/**
 * Names the exact dimension of coverage a beginner-report row is speaking
 * about. The backend authors these as English prose and they are the only thing
 * distinguishing one gap from the next: the surrounding row text is generated
 * from the gap's `kind` and `nextActionCode`, so two gaps sharing a kind are
 * told apart by this string alone.
 *
 * The implementation lives in `findingNarrative.ts` because the shared HTML
 * report names the same rows and Rust composes the identical sentence there —
 * that file is where the two languages are held to each other. Re-exported here
 * so the pages that show coverage keep importing it from one obvious place.
 *
 * The same holds for the limits a run was executed under: the report prints
 * them beside the coverage rows, so their labels moved to the same twin files.
 */
export { localizedCoverageDimension, localizedRequestedLimitName } from "./findingNarrative.ts";
