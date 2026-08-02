<#
    Generates the Ballast app icon.

    The mark (candidate B) is an open ring with a weight falling away from it: ballast is the
    dead weight you drop to move faster, which is exactly what the app does to a full disk.
    The ring is deliberately open at the bottom - the gap IS the space you just freed.

    Palette is the app's own: warm paper, graphite, one muted indigo accent. Indigo is chosen
    because the deletion-risk scale owns red -> orange -> yellow -> green, so the brand colour
    has to sit outside that ramp or the two colour languages fight each other.

    Output: Ballast.App/Assets/AppIcon.ico  (multi-resolution 16..256) + AppIcon-256.png
        powershell -ExecutionPolicy Bypass -File tools\make-icon.ps1
#>

Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot

# Resolved from the script's own location, so it works from any working directory.
$assets = Join-Path $root 'Ballast.App\Assets'

$icoPath = Join-Path $assets 'AppIcon.ico'
$pngPath = Join-Path $assets 'AppIcon-256.png'
New-Item -ItemType Directory -Path $assets -Force | Out-Null

$Paper  = [System.Drawing.Color]::FromArgb(255, 250, 249, 245)
$Ink    = [System.Drawing.Color]::FromArgb(255,  28,  27,  25)
$Accent = [System.Drawing.Color]::FromArgb(255,  79,  70, 184)

function New-RoundedPath([double]$x, [double]$y, [double]$w, [double]$h, [double]$r) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = $r * 2
    $p.AddArc($x,           $y,           $d, $d, 180, 90)
    $p.AddArc($x + $w - $d, $y,           $d, $d, 270, 90)
    $p.AddArc($x + $w - $d, $y + $h - $d, $d, $d,   0, 90)
    $p.AddArc($x,           $y + $h - $d, $d, $d,  90, 90)
    $p.CloseFigure()
    return $p
}

function New-IconBitmap([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode   = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.Clear([System.Drawing.Color]::Transparent)

    # Warm paper tile, iOS-proportion rounding (~22%) which reads well on the Windows taskbar too.
    $pad = [Math]::Max(1.0, $size * 0.02)
    $box = $size - 2 * $pad
    $g.FillPath((New-Object System.Drawing.SolidBrush($Paper)),
                (New-RoundedPath $pad $pad $box $box ($box * 0.225)))

    $cx = $size * 0.5
    $cy = $size * 0.455
    $r  = $size * 0.265
    $thick = $size * 0.115

    # The ring. Sweeping 290 degrees from 125 leaves the gap at the bottom, under the weight.
    $pen = New-Object System.Drawing.Pen($Ink, $thick)
    $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $pen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
    $g.DrawArc($pen, ($cx - $r), ($cy - $r), (2 * $r), (2 * $r), 125, 290)
    $pen.Dispose()

    # The released weight. The trailing dot only appears once there are pixels to spare for it -
    # at 16px it would just smear into the main one.
    $dot = $size * 0.105
    $g.FillEllipse((New-Object System.Drawing.SolidBrush($Accent)),
                   ($cx - $dot / 2), ($size * 0.735), $dot, $dot)

    if ($size -ge 32) {
        $g.FillEllipse(
            (New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(110, 79, 70, 184))),
            ($cx - $dot * 0.30), ($size * 0.885), ($dot * 0.6), ($dot * 0.6))
    }

    $g.Dispose()
    return $bmp
}

# ---- assemble a real multi-resolution ICO with PNG-compressed entries ----
$sizes = @(16, 24, 32, 48, 64, 128, 256)
$payloads = @()

foreach ($s in $sizes) {
    $bmp = New-IconBitmap $s
    $ms  = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $payloads += , @{ Size = $s; Bytes = $ms.ToArray() }
    if ($s -eq 256) { $bmp.Save($pngPath, [System.Drawing.Imaging.ImageFormat]::Png) }
    $ms.Dispose(); $bmp.Dispose()
}

$fs = [System.IO.File]::Create($icoPath)
$bw = New-Object System.IO.BinaryWriter($fs)

$bw.Write([UInt16]0)                 # reserved
$bw.Write([UInt16]1)                 # type 1 = icon
$bw.Write([UInt16]$payloads.Count)

$offset = 6 + 16 * $payloads.Count
foreach ($p in $payloads) {
    $dim = if ($p.Size -ge 256) { 0 } else { $p.Size }   # 0 means 256 in the ICO format
    $bw.Write([Byte]$dim); $bw.Write([Byte]$dim)
    $bw.Write([Byte]0);    $bw.Write([Byte]0)
    $bw.Write([UInt16]1);  $bw.Write([UInt16]32)
    $bw.Write([UInt32]$p.Bytes.Length)
    $bw.Write([UInt32]$offset)
    $offset += $p.Bytes.Length
}
foreach ($p in $payloads) { $bw.Write($p.Bytes) }

$bw.Flush(); $bw.Dispose(); $fs.Dispose()

Write-Output ("icon : " + $icoPath + "  (" + [math]::Round((Get-Item $icoPath).Length/1KB,1) + " KB, " + ($sizes -join '/') + ")")
Write-Output ("png  : " + $pngPath)
