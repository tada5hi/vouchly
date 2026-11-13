export type TimeoutSignal = {
    signal: AbortSignal,
    clear: () => void,
};
