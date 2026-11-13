/** WildDuck webhook payload validation. Only the routing identifiers are read; message metadata is ignored. */

export const SUPPORTED_EVENTS = ['marked.spam', 'marked.ham'] as const;
export type TrainingEvent = (typeof SUPPORTED_EVENTS)[number];

const OBJECT_ID = /^[0-9a-f]{24}$/i;
/** WildDuck delivery ids are `<ObjectId>:<counter>`; logged only when they have exactly this shape. */
const DELIVERY_ID = /^[0-9a-f]{24}:[0-9]{1,10}$/;
const EVENT_NAME = /^[a-z]{1,32}(?:\.[a-z]{1,32}){0,3}$/;

export interface TrainingRequest {
    readonly ev: TrainingEvent;
    /** Lower-cased 24-hex ObjectId. */
    readonly user: string;
    /** Lower-cased 24-hex ObjectId. */
    readonly mailbox: string;
    /** IMAP UID (WildDuck sends the UID in `message` for marked.* events). */
    readonly uid: number;
    readonly deliveryId?: string;
}

export type PayloadResult =
    | { readonly kind: 'train'; readonly request: TrainingRequest }
    | { readonly kind: 'ignored'; readonly ev?: string; readonly deliveryId?: string }
    | { readonly kind: 'invalid'; readonly reason: string; readonly deliveryId?: string };

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

export function parsePayload(value: unknown): PayloadResult {
    if (!isRecord(value)) {
        return { kind: 'invalid', reason: 'not_an_object' };
    }
    const deliveryId = typeof value['id'] === 'string' && DELIVERY_ID.test(value['id']) ? value['id'] : undefined;
    const withDelivery = deliveryId ? { deliveryId } : {};
    const ev = value['ev'];
    if (typeof ev !== 'string') {
        return { kind: 'invalid', reason: 'invalid_event', ...withDelivery };
    }
    if (!(SUPPORTED_EVENTS as readonly string[]).includes(ev)) {
        return { kind: 'ignored', ...(EVENT_NAME.test(ev) ? { ev } : {}), ...withDelivery };
    }
    const { user, mailbox, message } = value;
    if (typeof user !== 'string' || !OBJECT_ID.test(user)) {
        return { kind: 'invalid', reason: 'invalid_user', ...withDelivery };
    }
    if (typeof mailbox !== 'string' || !OBJECT_ID.test(mailbox)) {
        return { kind: 'invalid', reason: 'invalid_mailbox', ...withDelivery };
    }
    if (typeof message !== 'number' || !Number.isSafeInteger(message) || message <= 0) {
        return { kind: 'invalid', reason: 'invalid_message', ...withDelivery };
    }
    return { kind: 'train', request: { ev: ev as TrainingEvent, user: user.toLowerCase(), mailbox: mailbox.toLowerCase(), uid: message, ...withDelivery } };
}
