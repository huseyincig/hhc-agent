# src/shell (reserved)

Shell execution currently lives in `../client/client.mjs`
(`executeShellJob`). Planned extraction: move the executor here behind the
same admission/cwd/timeout contract without changing the wire shape.
Tracked follow-up — do not add new shell surface until the move lands.
