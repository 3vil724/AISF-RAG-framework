from stegano import lsb

carrier_image = "benign_image.png"
poisoned_image = "poisoned_image.png"
secret_payload = "MENTOR_REVIEW_CRITICAL_PAYLOAD_ACTIVE"

print(f"--- Injecting Payload into {carrier_image} ---")

try:
    secret = lsb.hide(carrier_image, secret_payload)
    secret.save(poisoned_image)

    print(f"Success! Mock attack image saved as: {poisoned_image}")

    extracted_message = lsb.reveal(poisoned_image)
    print(f"Verification - Extracted Payload: {extracted_message}")
except Exception as e:
    print(f"Error generating payload image: {e}")
