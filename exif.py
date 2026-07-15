"""Local image EXIF metadata extraction: camera info, timestamps, GPS."""


def _dms_to_decimal(dms):
    """Converts EXIF's (degrees, minutes, seconds) GPS format to a single decimal number."""
    degrees, minutes, seconds = dms
    return float(degrees) + float(minutes) / 60.0 + float(seconds) / 3600.0


def extract_exif(image_path):
    """
    Reads EXIF metadata from a local image: camera make/model, creation
    timestamp, software used, and GPS coordinates if present. Local file
    only, not a URL - downloading arbitrary images is a different, riskier
    feature (fetching untrusted remote files) that isn't in scope here.

    Many images have no EXIF at all by the time you get them - social
    media platforms, messaging apps, and screenshot tools routinely strip
    it either for privacy or because it was never there to begin with.
    That's reported as a normal outcome, not an error.
    """
    print(f"\n[*] Extracting EXIF metadata from '{image_path}'...")
    result = {
        "file": image_path, "has_exif": False, "format": None, "dimensions": None,
        "camera_make": None, "camera_model": None, "created": None, "software": None,
        "gps": None, "warnings": [],
    }

    try:
        from PIL import Image, ExifTags
        from PIL.ExifTags import TAGS, GPSTAGS
    except ImportError:
        print("    [!] Pillow not installed, skipping EXIF extraction. Run: pip install Pillow")
        result["warnings"].append("Pillow not installed")
        return result

    try:
        # Pillow has no built-in HEIC/HEIF support (the default format for
        # iPhone photos since iOS 11) - this registers a HEIF opener so
        # Image.open() below can read them like any other format. Optional:
        # if pillow-heif isn't installed, HEIC files just fail to open below
        # with the normal "could not open image" path, same as any other
        # unsupported format.
        import pillow_heif
        pillow_heif.register_heif_opener()
    except ImportError:
        pass

    try:
        img = Image.open(image_path)
    except FileNotFoundError:
        print(f"    [!] File not found: {image_path}")
        result["warnings"].append("File not found")
        return result
    except Exception as e:
        print(f"    [!] Could not open image: {e.__class__.__name__}: {e}")
        result["warnings"].append(f"Could not open image: {e.__class__.__name__}: {e}")
        return result

    result["format"] = img.format
    result["dimensions"] = f"{img.width}x{img.height}"

    exif_data = img.getexif()
    if not exif_data:
        print("    [-] No EXIF data present (common - many platforms strip it on upload/re-save)")
        result["warnings"].append("No EXIF data found in this image")
        return result

    result["has_exif"] = True
    # exif values can include raw bytes (e.g. MakerNote, thumbnails) that
    # aren't JSON-serializable - convert those to a short description
    # instead of the raw blob so the report doesn't break or bloat.
    tags = {}
    for tag_id, value in exif_data.items():
        tag_name = TAGS.get(tag_id, tag_id)
        if isinstance(value, bytes):
            value = f"<binary data, {len(value)} bytes>"
        tags[tag_name] = value

    # getexif() only returns the top-level (0th IFD) tags - Make/Model/
    # Software live there, but DateTimeOriginal and other detailed shooting
    # info live in the "Exif" sub-IFD, same nested-pointer structure as GPS.
    try:
        exif_ifd = exif_data.get_ifd(ExifTags.IFD.Exif)
        for tag_id, value in exif_ifd.items():
            tag_name = TAGS.get(tag_id, tag_id)
            if isinstance(value, bytes):
                value = f"<binary data, {len(value)} bytes>"
            tags[tag_name] = value
    except Exception:
        pass  # no Exif sub-IFD present - fine, just means less detail available

    result["camera_make"] = tags.get("Make")
    result["camera_model"] = tags.get("Model")
    result["created"] = tags.get("DateTimeOriginal") or tags.get("DateTime")
    result["software"] = tags.get("Software")

    print(f"    [+] Format: {result['format']}, Dimensions: {result['dimensions']}")
    if result["camera_make"] or result["camera_model"]:
        print(f"    [+] Camera: {result['camera_make']} {result['camera_model']}")
    if result["created"]:
        print(f"    [+] Created: {result['created']}")
    if result["software"]:
        print(f"    [+] Software: {result['software']}")

    # GPS lives in a nested IFD (Image File Directory), not the top-level tags
    try:
        gps_ifd = exif_data.get_ifd(ExifTags.IFD.GPSInfo)
        if gps_ifd:
            gps_tags = {GPSTAGS.get(k, k): v for k, v in gps_ifd.items()}
            lat, lat_ref = gps_tags.get("GPSLatitude"), gps_tags.get("GPSLatitudeRef")
            lon, lon_ref = gps_tags.get("GPSLongitude"), gps_tags.get("GPSLongitudeRef")
            if lat and lon:
                lat_deg = _dms_to_decimal(lat)
                if lat_ref == "S":
                    lat_deg = -lat_deg
                lon_deg = _dms_to_decimal(lon)
                if lon_ref == "W":
                    lon_deg = -lon_deg
                result["gps"] = {
                    "latitude": round(lat_deg, 6),
                    "longitude": round(lon_deg, 6),
                    "maps_url": f"https://www.google.com/maps?q={lat_deg:.6f},{lon_deg:.6f}",
                }
                print(f"    [!] GPS location found: {lat_deg:.6f}, {lon_deg:.6f}")
                print(f"        {result['gps']['maps_url']}")
    except Exception as e:
        result["warnings"].append(f"GPS parsing failed: {e.__class__.__name__}")

    return result
