from stegano import lsb

carrier_image = "benign_image.png"     # Put a normal PNG in your folder
poisoned_image = "poisoned_image.png"  # This will be our mock attack file
secret_payload = "MENTOR_REVIEW_CRITICAL_PAYLOAD_ACTIVE"

print(f"--- Injecting Payload into {carrier_image} ---")

# 1. Hide the secret text inside the image pixels
secret = lsb.hide(carrier_image, secret_payload)
secret.save(poisoned_image)

print(f"Success! Mock attack image saved as: {poisoned_image}")

# 2. Verify the payload is actually in there
extracted_message = lsb.reveal(poisoned_image)
print(f"Verification - Extracted Payload: {extracted_message}")
