import os
import random
import io
import logging
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from PIL import Image, ImageDraw, ImageChops

# Terminal Layout Color Constants
GREEN = "\033[0;32m"
CYAN = "\033[0;36m"
YELLOW = "\033[0;33m"
NC = "\033[0m"

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s', datefmt='%H:%M:%S')

SCAN_DOMAINS = ["Archived_Dossier", "Scan_Collection", "Historical_Registry", "Classified_Index"]
SCAN_TYPES = ["Photocopies", "Blueprints", "Records", "Manuscripts"]

def generate_scan_title():
    """Generates names matching scanned file archives."""
    return f"{random.choice(SCAN_DOMAINS)}_{random.choice(SCAN_TYPES)}_{random.randint(100,999)}.pdf"

def generate_synthetic_scan_image(width=1200, height=1600):
    """
    Creates a synthetic 'scanned paper' image layer completely in memory.
    Draws structural lines, text blocks, and subtle color noise to simulate raw data weight.
    """
    # 1. Create a base background image (off-white/light gray to simulate paper texture)
    base_color = (random.randint(240, 245), random.randint(238, 243), random.randint(230, 238))
    img = Image.new("RGB", (width, height), color=base_color)
    draw = ImageDraw.Draw(img)
    
    # 2. Draw mock 'schematic' grid lines or structural boundaries
    grid_spacing = random.choice([40, 60, 80])
    for x in range(0, width, grid_spacing):
        draw.line([(x, 0), (x, height)], fill=(225, 225, 225), width=1)
    for y in range(0, height, grid_spacing):
        draw.line([(0, y), (width, y)], fill=(225, 225, 225), width=1)

    # 3. Draw chaotic shapes to simulate blueprints, diagrams, or redacted markers
    for _ in range(random.randint(2, 5)):
        x1 = random.randint(50, width - 300)
        y1 = random.randint(100, height - 400)
        x2 = x1 + random.randint(150, 250)
        y2 = y1 + random.randint(150, 250)
        
        # Mix fills: solid black blocks (redactions) or hollow shapes (diagrams)
        if random.random() > 0.5:
            draw.rectangle([x1, y1, x2, y2], fill=(40, 40, 40)) # Redacted text block mimic
        else:        
            draw.ellipse([x1, y1, x2, y2], outline=(100, 110, 150), width=4)

    # 4. Add heavy per-pixel noise to balloon the compressed image size naturally
    # High entropy noise forces the JPEG encoder to use more bytes per block
    noise = Image.effect_noise((width, height), random.randint(15, 30)).convert("RGB")
    img = ImageChops.multiply(img, noise)

    # Save to a memory stream instead of writing to physical disk
    img_byte_arr = io.BytesIO()
    # JPEG format with variable quality sets the target baseline structural weight
    img.save(img_byte_arr, format='JPEG', quality=random.choice([85, 92, 95]))
    img_byte_arr.seek(0)
    
    return img_byte_arr

def create_image_only_pdf(target_path, target_pages):
    """
    Assembles a completely image-driven PDF document where each page 
    is an independent, high-entropy simulated graphic scan layer.
    """
    try:
        c = canvas.Canvas(target_path, pagesize=letter)
        
        for _ in range(target_pages):
            # Generate the image asset dynamically in RAM
            img_stream = generate_synthetic_scan_image()
            
            # Wrap memory stream inside reportlab Reader wrapper
            from reportlab.lib.utils import ImageReader
            img_reader = ImageReader(img_stream)
            
            # Draw image to scale, flooding the entire paper boundary canvas matrix
            c.drawImage(img_reader, 0, 0, width=letter[0], height=letter[1])
            c.showPage()
            
        c.save()
        return True
    except Exception as e:
        logging.error(f"Failed generating image-driven carrier {target_path}: {e}")
        return False

def build_image_vault(output_dir, num_files=5, min_pages=4, max_pages=12):
    """
    Spawns high-capacity image repositories optimized for massive payload hiding operations.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    logging.info(f"{CYAN}[IMAGE FACTORY]{NC} Composing {num_files} heavy scan-based PDF target carriers...")
    logging.info("-" * 90)
    
    success_count = 0
    total_bytes = 0
    
    for idx in range(1, num_files + 1):
        filename = generate_scan_title()
        target_path = os.path.join(output_dir, filename)
        
        chosen_pages = random.randint(min_pages, max_pages)
        
        if create_image_only_pdf(target_path, chosen_pages):
            actual_size_bytes = os.path.getsize(target_path)
            total_bytes += actual_size_bytes
            actual_size_mb = actual_size_bytes / (1024 * 1024)
            success_count += 1
            logging.info(f"  {GREEN}{idx:02d}.{NC} Created: {os.path.basename(target_path):<50} | {chosen_pages:02d} Pages | ({actual_size_mb:.2f} MB)")
            
    logging.info("-" * 90)
    logging.info(f"{GREEN}[COMPLETE]{NC} Repository populated. Total Carrier Volume: {total_bytes / (1024 * 1024):.2f} MB")

if __name__ == "__main__":
    # Setup test path directories
    IMAGE_TARGET_DIR = "./synthetic_scans"
    build_image_vault(IMAGE_TARGET_DIR, num_files=6, min_pages=5, max_pages=15)