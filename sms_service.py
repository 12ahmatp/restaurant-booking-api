
"""
sms_service.py
~~~~~~~~~~~~~~

Async helper for sending SMS notifications via the smsnotif.id API.

API Reference:
    POST https://www.smsnotif.id/api/messages
    Headers:
        Authorization: Bearer <API_KEY>
        Content-Type:  application/json
        Accept:        application/json
    Body:
        {"to": "+628...", "message": "lorem ipsum"}

Environment Variables:
    SMSNOTIF_API_KEY  –  Your API key from smsnotif.id dashboard.
                         If not set, SMS sending is silently skipped.

Usage:
    from sms_service import send_sms

    result = await send_sms("+6281234567890", "Hello from our restaurant!")
"""

import os
import httpx

SMSNOTIF_API_KEY = os.getenv("SMSNOTIF_API_KEY")
SMSNOTIF_URL = "https://www.smsnotif.id/api/messages"


async def send_sms(phone_number: str, message: str) -> dict | None:
    """
    Send an SMS message through the smsnotif.id API.

    Args:
        phone_number: Recipient phone number in international format (e.g. "+6281234567890").
        message:      The text body of the SMS to send.

    Returns:
        dict:  The parsed JSON response from the API on success.
        None:  If the API key is missing, the request fails, or any error occurs.
               Errors are logged to stdout but never raised, so calling code
               is never interrupted by SMS failures.
    """

    # ── Guard: skip gracefully if no API key is configured ──────────────
    if not SMSNOTIF_API_KEY:
        print("WARNING: SMSNOTIF_API_KEY is not set — skipping SMS notification.")
        return None

    # ── Build and send the request ──────────────────────────────────────
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                SMSNOTIF_URL,
                headers={
                    "Authorization": f"Bearer {SMSNOTIF_API_KEY}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                json={
                    "to": phone_number,
                    "message": message,
                },
                timeout=15.0,
            )

            # Raise for 4xx / 5xx status codes
            response.raise_for_status()

            return response.json()

    # ── Handle HTTP errors (4xx, 5xx) from the API ─────────────────────
    except httpx.HTTPStatusError as e:
        print(
            f"SMS API HTTP error {e.response.status_code}: {e.response.text}"
        )
        return None

    # ── Handle network / timeout / unexpected errors ───────────────────
    except httpx.TimeoutException:
        print("SMS API request timed out after 15 seconds.")
        return None

    except Exception as e:
        print(f"SMS send failed with unexpected error: {e}")
        return None
