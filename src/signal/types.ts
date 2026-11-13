export type TimeoutSignal = {
    signal: AbortSignal,
    clear: () => void,
};

export type DeadlineSignal = TimeoutSignal & {
    /**
     * Moves the deadline (a Date.now() timestamp) later; an earlier one is ignored.
     */
    extend: (deadline: number) => void,
};
