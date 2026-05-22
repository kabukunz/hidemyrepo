import os
import random
import uuid
import logging
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Terminal ANSI layouts
GREEN = "\033[0;32m"
CYAN = "\033[0;36m"
YELLOW = "\033[0;33m"
NC = "\033[0m"

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s', datefmt='%H:%M:%S')

# Fake technical dictionary elements to construct realistic names
DOMAINS = ["Optimization", "Stochastic", "Geometric", "Quantum", "Distributed", "Computational"]
TOPICS = ["Manifolds", "Topologies", "Neural Networks", "Approximations", "Simulations", "Transforms"]
SUFFIXES = ["Framework", "Analysis", "Review", "Methodology", "Principles", "Algorithms"]

def generate_academic_title():
    """Generates an authentic-looking computer science / math research document name."""
    parts = [random.choice(DOMAINS), random.choice(TOPICS), "for", random.choice(DOMAINS), random.choice(SUFFIXES)]
    # Randomly append variations like trailing hyphens or editions
    title = " ".join(parts)
    if random.random() > 0.7:
        title += f" Vol {random.randint(1, 5)}"
    return f"{title}.pdf"

def create_synthetic_pdf(target_path, target_size_kb):
    """
    Generates a mathematically valid, readable PDF file structured to match a requested target size floor.
    """
    try:
        # Build standard PDF document object via Canvas
        c = canvas.Canvas(target_path, pagesize=letter)
        c.setTitle(os.path.basename(target_path).replace(".pdf", ""))
        c.setAuthor("Synthetic Carrier Engine v1.0")
        
        page_num = 1
        
        # Estimate words/lines needed to expand the physical size constraint
        # A single page of ReportLab baseline elements generally hovers around 4-8 KB
        approx_pages = max(1, int(target_size_kb / 6))
        
        for _ in range(approx_pages):
            # Write a generic document header
            c.setFont("Helvetica-Bold", 14)
            c.drawString(50, 750, f"Section {page_num}: Automated Architecture Deep-Dive")
            
            c.setFont("Helvetica", 10)
            y_position = 720
            
            # Fill the page with random technical filler paragraphs
            for line_idx in range(45):
                if y_position < 50:
                    break
                text_line = f"[{uuid.uuid4().hex[:8].upper()}] Local tracking matrix index point validation sequence delta: " \
                            f"alpha={random.random():.4f}, beta={random.random():.4f}. " \
                            f"Verify internal steganographic containment boundaries."
                c.drawString(50, y_position, text_line)
                y_position -= 15
            
            # Draw a decorative chart placeholder block to increase data densities naturally
            c.setLineWidth(1)
            c.rect(50, 100, 500, 150, stroke=1, fill=0)
            c.drawString(60, 235, "Figure Mapping Constraint Array [Reference Index Vector]")
            
            # Page Footer
            c.drawString(550, 30, f"Page {page_num}")
            c.showPage()
            page_num += 1
            
        c.save()
        
        # Pad up precisely with trailing null spaces if strict minimal tracking weights are needed
        current_size = os.path.getsize(target_path)
        needed_bytes = (target_size_kb * 1024) - current_size
        if needed_bytes > 0:
            with open(target_path, "ab") as f:
                f.write(b"\x00" * needed_bytes)
                
        return True
    except Exception as e:
        logging.error(f"Failed generating individual file {target_path}: {e}")
        return False

def build_vault(output_dir, num_files=15, min_size_mb=5, max_size_mb=45):
    """
    Generates a massive multi-gigabyte repository of unique testing assets.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    logging.info(f"{CYAN}[FACTORY]{NC} Spawning {num_files} synthetic target carriers into '{output_dir}'...")
    logging.info("-" * 90)
    
    success_count = 0
    total_generated_bytes = 0
    
    for idx in range(1, num_files + 1):
        filename = generate_academic_title()
        # Ensure filenames don't accidentally stomp each other out if duplicates generate
        target_path = os.path.join(output_dir, filename)
        if os.path.exists(target_path):
            target_path = target_path.replace(".pdf", f"_{idx}.pdf")
            
        # Select an unpredictable size floor within range boundaries
        chosen_size_kb = random.randint(min_size_mb * 1024, max_size_mb * 1024)
        
        if create_synthetic_pdf(target_path, chosen_size_kb):
            actual_size_mb = os.path.getsize(target_path) / (1024 * 1024)
            total_generated_bytes += os.path.getsize(target_path)
            success_count += 1
            logging.info(f"  {GREEN}{idx:02d}.{NC} Created: {os.path.basename(target_path):<60} ({actual_size_mb:.2f} MB)")
            
    logging.info("-" * 90)
    logging.info(f"{GREEN}[COMPLETE]{NC} Successfully built {success_count}/{num_files} testing assets. Total Pool Size: {total_generated_bytes / (1024 * 1024):.2f} MB")

if __name__ == "__main__":
    # Test execution layout parameters
    TARGET_DIR = "./synthetic_pool"
    build_vault(TARGET_DIR, num_files=10, min_size_mb=10, max_size_mb=50)