import pytest
from PIL import Image
from PIL.ExifTags import Base, IFD
from PIL.TiffImagePlugin import IFDRational

import exif as mod
from exif import _dms_to_decimal


class TestDmsToDecimal:
    def test_zero(self):
        assert _dms_to_decimal((0, 0, 0)) == 0.0

    def test_known_value(self):
        # 40 deg 44 min 54 sec -> 40.7483 (a real coordinate, not a round number)
        assert _dms_to_decimal((40, 44, 54)) == pytest.approx(40.7483, abs=1e-4)

    def test_accepts_float_like_components(self):
        # PIL hands back IFDRational objects that behave like floats
        assert _dms_to_decimal((40.0, 44.0, 54.0)) == pytest.approx(40.7483, abs=1e-4)


def test_file_not_found():
    result = mod.extract_exif("/nonexistent/path/does-not-exist.jpg")
    assert result["has_exif"] is False
    assert "File not found" in result["warnings"]


def test_image_without_exif(tmp_path):
    path = tmp_path / "plain.jpg"
    Image.new("RGB", (20, 10), color="blue").save(path)

    result = mod.extract_exif(str(path))
    assert result["has_exif"] is False
    assert result["format"] == "JPEG"
    assert result["dimensions"] == "20x10"
    assert "No EXIF data found in this image" in result["warnings"]


def test_image_with_camera_and_gps(tmp_path):
    path = tmp_path / "with_exif.jpg"
    img = Image.new("RGB", (10, 10), color="red")
    exif = Image.Exif()
    exif[Base.Make.value] = "TestMake"
    exif[Base.Model.value] = "TestModel"
    exif.get_ifd(IFD.Exif)[Base.DateTimeOriginal.value] = "2024:05:02 14:31:09"
    gps_ifd = exif.get_ifd(IFD.GPSInfo)
    gps_ifd[1] = "N"
    gps_ifd[2] = (IFDRational(40, 1), IFDRational(44, 1), IFDRational(54, 1))
    gps_ifd[3] = "W"
    gps_ifd[4] = (IFDRational(73, 1), IFDRational(59, 1), IFDRational(8, 1))
    img.save(path, exif=exif)

    result = mod.extract_exif(str(path))
    assert result["has_exif"] is True
    assert result["camera_make"] == "TestMake"
    assert result["camera_model"] == "TestModel"
    assert result["created"] == "2024:05:02 14:31:09"
    assert result["gps"]["latitude"] == pytest.approx(40.7483, abs=1e-3)
    assert result["gps"]["longitude"] == pytest.approx(-73.9856, abs=1e-3)
    assert result["gps"]["maps_url"].startswith("https://www.google.com/maps?q=")


def test_corrupted_file_is_not_found_but_reported_as_a_warning(tmp_path):
    path = tmp_path / "not_really_an_image.jpg"
    path.write_bytes(b"this is not image data at all")

    result = mod.extract_exif(str(path))
    assert result["has_exif"] is False
    assert any("Could not open image" in w for w in result["warnings"])


def test_exif_present_without_gps_leaves_gps_none(tmp_path):
    path = tmp_path / "camera_only.jpg"
    img = Image.new("RGB", (10, 10), color="red")
    exif = Image.Exif()
    exif[Base.Make.value] = "TestMake"
    img.save(path, exif=exif)

    result = mod.extract_exif(str(path))
    assert result["has_exif"] is True
    assert result["camera_make"] == "TestMake"
    assert result["gps"] is None


def test_partial_gps_data_does_not_produce_a_coordinate(tmp_path):
    # only latitude present, no longitude - extract_exif requires both
    # before reporting a GPS location, since half a coordinate is useless
    path = tmp_path / "partial_gps.jpg"
    img = Image.new("RGB", (10, 10), color="red")
    exif = Image.Exif()
    gps_ifd = exif.get_ifd(IFD.GPSInfo)
    gps_ifd[1] = "N"
    gps_ifd[2] = (IFDRational(40, 1), IFDRational(44, 1), IFDRational(54, 1))
    img.save(path, exif=exif)

    result = mod.extract_exif(str(path))
    assert result["gps"] is None


def test_south_and_west_refs_negate_coordinates(tmp_path):
    path = tmp_path / "southwest.jpg"
    img = Image.new("RGB", (10, 10), color="green")
    exif = Image.Exif()
    gps_ifd = exif.get_ifd(IFD.GPSInfo)
    gps_ifd[1] = "S"
    gps_ifd[2] = (IFDRational(10, 1), IFDRational(0, 1), IFDRational(0, 1))
    gps_ifd[3] = "W"
    gps_ifd[4] = (IFDRational(20, 1), IFDRational(0, 1), IFDRational(0, 1))
    img.save(path, exif=exif)

    result = mod.extract_exif(str(path))
    assert result["gps"]["latitude"] < 0
    assert result["gps"]["longitude"] < 0
