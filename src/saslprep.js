// SASLprep (RFC 4013) without fs or Node-only dependencies, so the library loads
// in browser bundles. Always behaves like saslprep's allowUnassigned: true.

import {
    commonly_mapped_to_nothing,
    non_ASCII_space_characters,
    prohibited_characters,
    bidirectional_r_al,
    bidirectional_l,
} from './saslprep-tables.js';

// Binary search over sorted inclusive [start, end, ...] ranges.
function inRanges(ranges, cp) {
    let lo = 0, hi = ranges.length / 2 - 1;
    while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (cp < ranges[mid * 2]) hi = mid - 1;
        else if (cp > ranges[mid * 2 + 1]) lo = mid + 1;
        else return true;
    }
    return false;
}

export default function saslprep(input) {
    if (typeof input !== 'string') throw new TypeError('Expected string.');
    if (input.length === 0) return '';

    // RFC 4013 §2.1 mapping: non-ASCII spaces to U+0020, "commonly mapped to nothing" removed.
    let mapped = '';
    for (const ch of input) {
        const cp = ch.codePointAt(0);
        if (inRanges(non_ASCII_space_characters, cp)) mapped += ' ';
        else if (!inRanges(commonly_mapped_to_nothing, cp)) mapped += ch;
    }

    // §2.2 normalization
    const normalized = mapped.normalize('NFKC');
    // A non-empty input that vanishes entirely would silently become the empty
    // password; the saslprep package (which this replaces) rejects it too.
    if (normalized.length === 0) throw new Error('Password consists only of characters mapped to nothing');
    const cps = Array.from(normalized, ch => ch.codePointAt(0));

    // §2.3 prohibited output
    if (cps.some(cp => inRanges(prohibited_characters, cp))) {
        throw new Error('Prohibited character, see https://tools.ietf.org/html/rfc4013#section-2.3');
    }

    // §2.4 bidirectional characters, RFC 3454 §6
    const isRAL = cps.map(cp => inRanges(bidirectional_r_al, cp));
    if (isRAL.includes(true)) {
        if (cps.some(cp => inRanges(bidirectional_l, cp))) {
            throw new Error(
                'String must not contain RandALCat and LCat at the same time,' +
                ' see https://tools.ietf.org/html/rfc3454#section-6'
            );
        }
        if (!isRAL[0] || !isRAL[isRAL.length - 1]) {
            throw new Error(
                'Bidirectional RandALCat character must be the first and the last' +
                ' character of the string, see https://tools.ietf.org/html/rfc3454#section-6'
            );
        }
    }

    return normalized;
}
