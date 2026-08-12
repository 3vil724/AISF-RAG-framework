import os
from PIL import Image


class VisualGate:
    def __init__(self):
        pass

    def cross_modal_neutralization(self, image_path: str) -> str:
        """
        Executes Cross-Modal Neutralization (CMN) on uploaded visual assets.
        Strips EXIF data, destroys LSB steganographic payloads, and flattens image
        channels into a clean RGB byte array.
        """
        output_path = f"{image_path}_safe.jpg"

        try:
            with Image.open(image_path) as img:
                # Convert image to clean RGB channel, stripping alpha/stego layers
                clean_img = Image.new("RGB", img.size, (255, 255, 255))
                clean_img.paste(img)

                # Re-encode and save as clean JPEG without metadata
                clean_img.save(output_path, "JPEG", quality=90, optimize=True)

            return output_path

        except Exception as e:
            raise RuntimeError(f"VisualGate Cross-Modal Neutralization Failed: {str(e)}")
