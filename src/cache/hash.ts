export async function hashToken(token: string): Promise<string> {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));

    let output = '';
    for (const byte of new Uint8Array(digest)) {
        output += byte.toString(16).padStart(2, '0');
    }

    return output;
}
