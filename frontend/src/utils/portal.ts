/**
 * LangBot application-center handoff markers.
 *
 * SqlBot is mounted under the same origin as LangBot (`/sqlbot/`), so leaving
 * SqlBot from the application center must end the LangBot session too. LangBot
 * owns that cleanup behind `?logout=1`, which keeps this module independent of
 * LangBot's storage keys.
 */

const PORTAL_SESSION_KEY = 'sqlbot_portal_session'

/** LangBot's unified login screen; `logout=1` asks it to clear its session. */
export const PORTAL_LOGOUT_URL = '/login?logout=1'

/** Remember that this SqlBot session was created by a LangBot portal ticket. */
export const markPortalSession = (): void => {
  localStorage.setItem(PORTAL_SESSION_KEY, '1')
}

export const isPortalSession = (): boolean => localStorage.getItem(PORTAL_SESSION_KEY) === '1'

export const clearPortalSession = (): void => {
  localStorage.removeItem(PORTAL_SESSION_KEY)
}
