import sys
import os
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import CarvingEngine, SignatureDatabase, save_html

def create_demo_image(path: str):
    """Create a simple disk image with some known files."""
    # Minimal PNG
    png = bytes.fromhex("89504E470D0A1A0A") + b"\x00" * 100 + bytes.fromhex("49454E44AE426082")
    
    # Minimal JPEG
    jpeg = bytes.fromhex("FFD8FFE0") + b"\x00" * 80 + bytes.fromhex("FFD9")
    
    # Minimal PDF
    pdf = b"%PDF-1.7\n" + b"Hello forensics!\n" + b"%%EOF"
    
    # Build image with padding
    image = bytearray()
    image.extend(b"\x00" * 512)  # Padding
    image.extend(png)
    image.extend(b"\xFF" * 256)
    image.extend(jpeg)
    image.extend(b"\xAA" * 128)
    image.extend(pdf)
    image.extend(b"\x00" * 512)
    
    Path(path).write_bytes(bytes(image))
    return len(image)

def main():
    print("\n" + "="*70)
    print("  Digital Forensics Tool v2.0 — Quick Demo")
    print("="*70 + "\n")
    
    # Create local directory instead of temp so user can view the report
    class KeepDir:
        def __enter__(self):
            import shutil
            self.d = os.path.join(str(Path(__file__).parent), "demo_workspace")
            if os.path.exists(self.d): shutil.rmtree(self.d)
            os.makedirs(self.d, exist_ok=True)
            return self.d
        def __exit__(self, *args): pass
        
    with KeepDir() as tmpdir:
        image_path = os.path.join(tmpdir, "demo.img")
        output_dir = os.path.join(tmpdir, "output")
        os.makedirs(output_dir)
        
        # Create demo image
        print("📁 Creating demo disk image...")
        size = create_demo_image(image_path)
        print(f"   Created {size:,} byte image at {image_path}\n")
        
        # Initialize engine
        print("🔧 Initializing carving engine...")
        db = SignatureDatabase()
        print(f"   Loaded {len(db.all)} file signatures\n")
        
        engine = CarvingEngine(
            sig_db=db,
            analyst="demo_user",
            compute_hashes=True,
            compute_entropy=True,
        )
        
        # Scan
        print("🔍 Scanning image...\n")
        result = engine.scan(image_path, source_type="file")
        
        # Display results
        print("="*70)
        print("  SCAN RESULTS")
        print("="*70)
        print(f"  Files found:     {result.files_found}")
        print(f"  Blocks scanned:  {result.blocks_scanned}")
        print(f"  Duration:        {result.duration_seconds:.3f}s")
        print(f"  Source hash:     {result.source_hash.md5 if result.source_hash else 'N/A'}")
        
        if result.carved_files:
            print(f"\n  Detected files:")
            print("  " + "-"*66)
            print(f"  {'#':<4} {'Type':<25} {'Offset':<12} {'Size':<10} {'Conf':<6}")
            print("  " + "-"*66)
            for f in result.carved_files:
                print(f"  {f.id:<4} {f.type_name:<25} 0x{f.start_offset:08X}   "
                      f"{f.size:>6} B   {f.confidence:.0%}")
                if f.metadata:
                    for k, v in f.metadata.items():
                        print(f"       ↳ {k}: {v}")
                if f.entropy:
                    enc = " [ENCRYPTED]" if f.entropy.is_encrypted else ""
                    print(f"       ↳ Entropy: {f.entropy.value:.2f} ({f.entropy.classification}){enc}")
        
        # Generate HTML report
        html_path = os.path.join(output_dir, "report.html")
        save_html(result, html_path, case_name="DEMO_CASE_001")
        print(f"\n  📄 HTML report: {html_path}")
        print(f"     (Open in browser to view)")
        
        print("\n" + "="*70)
        print("  Demo complete! Check the HTML report for full details.")
        print("="*70 + "\n")

if __name__ == "__main__":
    main()
