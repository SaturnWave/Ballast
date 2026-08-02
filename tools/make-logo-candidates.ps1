<#
    Renders four logo candidates side by side for review.

    Palette is the new "blend" direction: warm paper, graphite, one muted indigo accent.
    Indigo is chosen deliberately - the risk scale uses a red -> orange -> yellow -> green
    ramp, so the brand accent has to sit outside it or the two colour languages fight.

    Output: tools/logo-candidates.png
        powershell -ExecutionPolicy Bypass -File tools\make-logo-candidates.ps1
#>

Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$out  = Join-Path $PSScriptRoot 'logo-candidates.png'

$Ink      = [System.Drawing.Color]::FromArgb(255, 28, 27, 25)    # graphite
$InkSoft  = [System.Drawing.Color]::FromArgb(255, 62, 60, 56)
$Paper    = [System.Drawing.Color]::FromArgb(255, 250, 249, 245) # warm paper
$Accent   = [System.Drawing.Color]::FromArgb(255,  79,  70, 184) # muted indigo
$AccentLt = [System.Drawing.Color]::FromArgb(255, 124, 116, 220)

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

function New-Tile([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode   = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.Clear([System.Drawing.Color]::Transparent)
    return @{ Bmp = $bmp; G = $g }
}

# ---- A. Treemap monogram: nested asymmetric blocks, quoting the app's own map ----
function Draw-Treemap($g, $s) {
    $pad = $s * 0.02
    $box = $s - 2 * $pad
    $g.FillPath((New-Object System.Drawing.SolidBrush($Ink)), (New-RoundedPath $pad $pad $box $box ($box * 0.225)))

    $m = $s * 0.17
    $inner = $s - 2 * $m
    $gap = $s * 0.030

    # one dominant block, then progressively smaller ones - a real treemap silhouette
    $bigW = $inner * 0.58
    $g.FillPath((New-Object System.Drawing.SolidBrush($Paper)),
        (New-RoundedPath $m $m $bigW $inner ($s * 0.028)))

    $rx = $m + $bigW + $gap
    $rw = $inner - $bigW - $gap
    $topH = $inner * 0.56
    $g.FillPath((New-Object System.Drawing.SolidBrush($AccentLt)),
        (New-RoundedPath $rx $m $rw $topH ($s * 0.028)))

    $by = $m + $topH + $gap
    $bh = $inner - $topH - $gap
    $bw = ($rw - $gap) / 2
    $g.FillPath((New-Object System.Drawing.SolidBrush($Accent)),
        (New-RoundedPath $rx $by $bw $bh ($s * 0.028)))
    $g.FillPath((New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(150, 250, 249, 245))),
        (New-RoundedPath ($rx + $bw + $gap) $by $bw $bh ($s * 0.028)))
}

# ---- B. Ballast: a ring with weight released from it ----
function Draw-Ballast($g, $s) {
    $pad = $s * 0.02
    $box = $s - 2 * $pad
    $g.FillPath((New-Object System.Drawing.SolidBrush($Paper)), (New-RoundedPath $pad $pad $box $box ($box * 0.225)))

    $cx = $s * 0.5; $cy = $s * 0.46
    $r  = $s * 0.27
    $thick = $s * 0.115

    $pen = New-Object System.Drawing.Pen($Ink, $thick)
    $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $pen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
    # open ring: the gap is the space you just freed
    $g.DrawArc($pen, ($cx - $r), ($cy - $r), (2 * $r), (2 * $r), 125, 290)
    $pen.Dispose()

    # the released weight, falling away
    $dot = $s * 0.105
    $g.FillEllipse((New-Object System.Drawing.SolidBrush($Accent)),
        ($cx - $dot / 2), ($s * 0.735), $dot, $dot)
    $g.FillEllipse((New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(110, 79, 70, 184))),
        ($cx - $dot * 0.30), ($s * 0.885), ($dot * 0.6), ($dot * 0.6))
}

# ---- C. Descending bars: space coming down ----
function Draw-Bars($g, $s) {
    $pad = $s * 0.02
    $box = $s - 2 * $pad
    $g.FillPath((New-Object System.Drawing.SolidBrush($Ink)), (New-RoundedPath $pad $pad $box $box ($box * 0.225)))

    $m = $s * 0.20
    $w = $s - 2 * $m
    $barH = $s * 0.105
    $gap  = $s * 0.055
    $r    = $barH / 2

    $widths = @(1.0, 0.72, 0.44)
    $cols   = @($Paper, $AccentLt, $Accent)
    for ($i = 0; $i -lt 3; $i++) {
        $bw = $w * $widths[$i]
        $y  = $m + $i * ($barH + $gap) + $s * 0.06
        $g.FillPath((New-Object System.Drawing.SolidBrush($cols[$i])), (New-RoundedPath $m $y $bw $barH $r))
    }
}

# ---- D. Disk gauge: a ring showing how much came back ----
function Draw-Gauge($g, $s) {
    $pad = $s * 0.02
    $box = $s - 2 * $pad
    $g.FillPath((New-Object System.Drawing.SolidBrush($Paper)), (New-RoundedPath $pad $pad $box $box ($box * 0.225)))

    $cx = $s * 0.5; $cy = $s * 0.5
    $r  = $s * 0.28
    $thick = $s * 0.125

    $track = New-Object System.Drawing.Pen(([System.Drawing.Color]::FromArgb(38, 28, 27, 25)), $thick)
    $track.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $track.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
    $g.DrawArc($track, ($cx - $r), ($cy - $r), (2 * $r), (2 * $r), 135, 270)
    $track.Dispose()

    $fill = New-Object System.Drawing.Pen($Accent, $thick)
    $fill.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $fill.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
    $g.DrawArc($fill, ($cx - $r), ($cy - $r), (2 * $r), (2 * $r), 135, 168)
    $fill.Dispose()

    # solid centre so it reads as a disk, not a progress bar
    $ir = $s * 0.085
    $g.FillEllipse((New-Object System.Drawing.SolidBrush($Ink)), ($cx - $ir), ($cy - $ir), (2 * $ir), (2 * $ir))
}

# ---- compose the review sheet ----
$tile = 240
$labelH = 46
$cols = 4
$sheetW = $cols * $tile + ($cols + 1) * 28
$sheetH = $tile + $labelH + 56

$sheet = New-Object System.Drawing.Bitmap($sheetW, $sheetH, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$sg = [System.Drawing.Graphics]::FromImage($sheet)
$sg.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$sg.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
$sg.Clear([System.Drawing.Color]::FromArgb(255, 244, 243, 239))

$font  = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Regular)
$fontB = New-Object System.Drawing.Font("Segoe UI Semibold", 13)
$brushInk = New-Object System.Drawing.SolidBrush($Ink)
$fmt = New-Object System.Drawing.StringFormat
$fmt.Alignment = [System.Drawing.StringAlignment]::Center

$defs = @(
    @{ Name = "A - Treemap";  Draw = ${function:Draw-Treemap} },
    @{ Name = "B - Ballast";  Draw = ${function:Draw-Ballast} },
    @{ Name = "C - Bars";     Draw = ${function:Draw-Bars}    },
    @{ Name = "D - Gauge";    Draw = ${function:Draw-Gauge}   }
)

for ($i = 0; $i -lt $defs.Count; $i++) {
    $t = New-Tile $tile
    & $defs[$i].Draw $t.G $tile
    $x = 28 + $i * ($tile + 28)
    $sg.DrawImage($t.Bmp, $x, 28, $tile, $tile)
    $t.G.Dispose(); $t.Bmp.Dispose()

    $rect = New-Object System.Drawing.RectangleF($x, ($tile + 40), $tile, 24)
    $sg.DrawString($defs[$i].Name, $fontB, $brushInk, $rect, $fmt)
}

$sheet.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
$sg.Dispose(); $sheet.Dispose()
Write-Output ("wrote " + $out)
