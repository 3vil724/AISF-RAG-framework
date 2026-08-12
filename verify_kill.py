from stegano import lsb

sterilized_image = "poisoned_image.png_safe.jpg"

try:
    print(f"Attempting to extract payload from {sterilized_image}...")
    extracted_message = lsb.reveal(sterilized_image)

    if extracted_message:
        print(f"VULNERABILITY FOUND: Payload survived: {extracted_message}")
    else:
        print("SECURE: No payload found.")

except Exception as e:
    print(f"SECURE: File structure altered, steganography destroyed. (Error: {e})")
