/**
 * Feeds client — fetches trending stories and notifications from
 * the CF Worker D1 API. Falls back to the main Express backend.
 */

const CF_WORKER_URL = process.env.NEXT_PUBLIC_CF_WORKER_URL || '';
const API_URL = process.env.NEXT_PUBLIC_API_URL || '';

function feedsBase(): string {
    return CF_WORKER_URL || API_URL;
}

export interface TrendingStory {
    story_id: string;
    score: number;
    period: string;
    title?: string;
    content?: string;
    genre?: string;
    cover_image_url?: string;
    likes_count?: number;
    views_count?: number;
    author_username?: string;
    author_avatar?: string;
}

export interface Notification {
    id: string;
    user_id: string;
    type: string;
    title: string;
    body: string;
    read: number;
    metadata: string;
    created_at: string;
}

export async function fetchTrending(
    period: 'daily' | 'weekly' | 'alltime' = 'daily',
    limit = 20,
): Promise<TrendingStory[]> {
    try {
        const res = await fetch(
            `${feedsBase()}/api/feeds/trending?period=${period}&limit=${limit}`,
        );
        if (!res.ok) return [];
        const json = await res.json();
        return json.data || [];
    } catch {
        return [];
    }
}

export async function fetchNotifications(
    userId: string,
    unreadOnly = false,
    limit = 30,
): Promise<Notification[]> {
    try {
        const res = await fetch(
            `${feedsBase()}/api/feeds/notifications/${userId}?unread=${unreadOnly}&limit=${limit}`,
        );
        if (!res.ok) return [];
        const json = await res.json();
        return json.data || [];
    } catch {
        return [];
    }
}

export async function markNotificationRead(id: string): Promise<boolean> {
    try {
        const res = await fetch(`${feedsBase()}/api/feeds/notifications/${id}/read`, {
            method: 'POST',
        });
        return res.ok;
    } catch {
        return false;
    }
}

export async function markAllNotificationsRead(userId: string): Promise<boolean> {
    try {
        const res = await fetch(`${feedsBase()}/api/feeds/notifications/mark-all-read`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ userId }),
        });
        return res.ok;
    } catch {
        return false;
    }
}
