"""Build docs/assets/demo.gif from real captured terminal output.

Renders six frames, each a command line plus its actually-executed pytest
output, styled as a dark terminal screenshot with a caption bar explaining
what the frame proves. The commands are drawn from docs/DEMO_SCRIPT.md
(P3.20) but are not a 1:1 mapping of its four beats: frame 4 is a sub-item
of that doc's third beat, and frame 6 comes from its Prerequisites section
("the whole deterministic suite"). The pytest session header (working
directory, platform, etc.) is elided from every frame because it embeds an
absolute local path; the command line and the output below it are verbatim.

Usage:
    python tools/make_demo_gif.py

Requires Pillow (`pip install pillow`) -- not a repo dependency, dev-only.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = REPO_ROOT / "docs" / "assets" / "demo.gif"

CANVAS_W = 1000
# CANVAS_H and CAPTION_H are computed at runtime in main() from the tallest
# beat's rendered content (and the longest caption's natural wrap), then
# held fixed -- every frame shares the one resulting canvas size.
CANVAS_H = 0
CAPTION_H = 0
BG = (13, 17, 23)          # #0d1117
FG = (201, 209, 217)       # light terminal text
PROMPT = (63, 185, 80)     # green prompt marker
CAPTION_BG = (0, 0, 0, 160)
CAPTION_FG = (240, 240, 240)

FONT_CANDIDATES = [
    r"C:\Windows\Fonts\consola.ttf",  # Windows
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",  # Linux (Debian/Ubuntu)
    "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",  # Linux (RHEL/Fedora)
    "/System/Library/Fonts/Supplemental/Menlo.ttc",  # macOS
    "/System/Library/Fonts/Monaco.ttf",  # macOS (older)
]

_WARNED_NO_FONT = False


def load_font(size: int) -> ImageFont.FreeTypeFont:
    global _WARNED_NO_FONT
    for path in FONT_CANDIDATES:
        try:
            return ImageFont.truetype(path, size)
        except Exception:
            continue
    if not _WARNED_NO_FONT:
        print(
            "WARNING: no monospace font found in FONT_CANDIDATES; falling back "
            "to Pillow's bitmap default font. This changes text measurements "
            "and will produce a structurally different gif.",
            file=sys.stderr,
        )
        _WARNED_NO_FONT = True
    return ImageFont.load_default()


FONT_BODY = load_font(18)
FONT_CAPTION = load_font(20)

PAD = 24  # outer margin used both to measure and to render body text


BEATS = [
    {
        "cmd": "$ pytest tests/redteam/test_campaign.py::"
        "test_full_loop_yields_stored_exploit_and_filed_vuln_report -v",
        "output": (
            "tests/redteam/test_campaign.py::"
            "test_full_loop_yields_stored_exploit_and_filed_vuln_report PASSED [100%]\n"
            "\n"
            "============================== 1 passed in 0.09s =============================="
        ),
        "caption": (
            "One full pass through the chain: Orchestrator drives the Red "
            "Team against a stubbed vulnerable target, the Judge scores the "
            "response a success, and the exploit is stored and documented -- "
            "proving the six components propagate a finding end-to-end."
        ),
    },
    {
        "cmd": "$ pytest tests/redteam/test_judge_agent.py -v -k "
        "\"independence or deterministic_default or verdict_validates\"",
        "output": (
            "tests/redteam/test_judge_agent.py::"
            "test_verdict_validates_against_contract PASSED [ 33%]\n"
            "tests/redteam/test_judge_agent.py::"
            "test_deterministic_default_path_is_reproducible_no_model_call PASSED [ 66%]\n"
            "tests/redteam/test_judge_agent.py::"
            "test_independence_module_imports_no_red_team_or_sibling_agent_internals PASSED [100%]\n"
            "\n"
            "======================= 3 passed, 7 deselected in 0.07s ======================="
        ),
        "caption": (
            "The Judge is an independent confirmation gate: no direct import "
            "of Red Team or sibling-agent modules, deterministic by default, "
            "every verdict validated against the judge_verdict contract."
        ),
    },
    {
        "cmd": "$ pytest tests/redteam/test_regression.py -v -k "
        "\"reintroduced\"",
        "output": (
            "tests/redteam/test_regression.py::"
            "test_reintroduced_fixed_exploit_flagged_as_regression PASSED [ 50%]\n"
            "tests/redteam/test_regression.py::"
            "test_reintroduced_exploit_emits_error_valid_against_contract_schema PASSED [100%]\n"
            "\n"
            "======================= 2 passed, 4 deselected in 0.08s ======================="
        ),
        "caption": (
            "The regression harness catches backsliding: mark an exploit "
            "fixed, replay the identical attack sequence, and it is "
            "flagged as a reintroduction."
        ),
    },
    {
        "cmd": "$ pytest tests/redteam/test_campaign.py::"
        "test_regression_detected_is_surfaced -v",
        "output": (
            "tests/redteam/test_campaign.py::"
            "test_regression_detected_is_surfaced PASSED [100%]\n"
            "\n"
            "============================== 1 passed in 0.09s =============================="
        ),
        "caption": (
            "That same regression check also runs inside run_campaign: "
            "driven in-process against a stubbed target, a reintroduced "
            "exploit is surfaced mid-campaign, not only by the harness's "
            "own standalone test."
        ),
    },
    {
        "cmd": "$ pytest tests/redteam/test_campaign.py::"
        "test_budget_exceeded_stops_the_loop -v",
        "output": (
            "tests/redteam/test_campaign.py::"
            "test_budget_exceeded_stops_the_loop PASSED [100%]\n"
            "\n"
            "============================== 1 passed in 0.08s =============================="
        ),
        "caption": (
            "Failure degrades gracefully: hitting the budget cap halts the "
            "loop cleanly with zero further attempts -- no crash, no "
            "runaway spend."
        ),
    },
    {
        "cmd": "$ pytest tests/ -q",
        "output": (
            "........................................................................ [ 35%]\n"
            "........................................................................ [ 70%]\n"
            ".............................................................            [100%]\n"
            "205 passed in 0.63s"
        ),
        "caption": (
            "The whole deterministic suite -- 205 tests covering every "
            "beat above -- passes in well under a second. No live "
            "model, no target stack required."
        ),
    },
]


def wrap_words(
    draw: ImageDraw.ImageDraw, text: str, font, max_width: int, bound_height: int
) -> tuple[list[str], int]:
    """Shrink font size until the caption wraps to lines that fit max_width
    and bound_height, returning the wrapped lines and the font size used."""
    size = font.size
    lines: list[str] = []
    while size > 10:
        f = load_font(size)
        words = text.split()
        lines = []
        cur = ""
        for w in words:
            trial = (cur + " " + w).strip()
            bbox = draw.textbbox((0, 0), trial, font=f)
            if bbox[2] - bbox[0] <= max_width:
                cur = trial
            else:
                if cur:
                    lines.append(cur)
                cur = w
        if cur:
            lines.append(cur)
        line_h = f.getbbox("Ag")[3] - f.getbbox("Ag")[1] + 6
        total_h = line_h * len(lines)
        fits_width = all(
            draw.textbbox((0, 0), ln, font=f)[2] - draw.textbbox((0, 0), ln, font=f)[0] <= max_width
            for ln in lines
        )
        if total_h <= bound_height - 16 and fits_width:
            return lines, size
        size -= 1
    return lines, size


def wrap_chars(draw: ImageDraw.ImageDraw, text: str, font, max_width: int) -> list[str]:
    """Hard-wrap a single line of monospace text (terminal output has no
    word boundaries to rely on) to fit max_width."""
    if draw.textbbox((0, 0), text, font=font)[2] <= max_width:
        return [text]
    lines: list[str] = []
    cur = ""
    for ch in text:
        trial = cur + ch
        if draw.textbbox((0, 0), trial, font=font)[2] <= max_width:
            cur = trial
        else:
            lines.append(cur)
            cur = ch
    if cur:
        lines.append(cur)
    return lines


def layout_body(draw: ImageDraw.ImageDraw, beat: dict, draw_it: bool) -> int:
    """Lay out the prompt/command line + output body starting at y=PAD.

    Shared by the measurement pass (draw_it=False, just returns the height
    consumed) and the real render pass (draw_it=True, also paints the text).
    Returns the y-coordinate immediately after the last line drawn.
    """
    max_text_w = CANVAS_W - 2 * PAD
    y = PAD

    marker = "\u25a0"
    marker_w = draw.textbbox((0, 0), marker, font=FONT_BODY)[2] + 10
    line_h = FONT_BODY.getbbox("Ag")[3] - FONT_BODY.getbbox("Ag")[1] + 10

    cmd_lines = wrap_chars(draw, beat["cmd"], FONT_BODY, max_text_w - marker_w)
    for i, ln in enumerate(cmd_lines):
        if draw_it:
            if i == 0:
                draw.text((PAD, y), marker, font=FONT_BODY, fill=PROMPT)
            draw.text((PAD + marker_w, y), ln, font=FONT_BODY, fill=FG)
        y += line_h
    y += line_h // 2

    for line in beat["output"].split("\n"):
        for wrapped in wrap_chars(draw, line, FONT_BODY, max_text_w):
            if draw_it:
                draw.text((PAD, y), wrapped, font=FONT_BODY, fill=FG)
            y += line_h

    return y


def render_frame(beat: dict) -> Image.Image:
    img = Image.new("RGB", (CANVAS_W, CANVAS_H), BG)
    draw = ImageDraw.Draw(img, "RGBA")

    layout_body(draw, beat, draw_it=True)

    # Caption bar across the bottom ~22%.
    bar_top = CANVAS_H - CAPTION_H
    overlay = Image.new("RGBA", (CANVAS_W, CAPTION_H), CAPTION_BG)
    composited = Image.alpha_composite(
        img.crop((0, bar_top, CANVAS_W, CANVAS_H)).convert("RGBA"), overlay
    ).convert("RGB")
    img.paste(composited, (0, bar_top))

    draw = ImageDraw.Draw(img, "RGBA")
    lines, size = wrap_words(draw, beat["caption"], FONT_CAPTION, CANVAS_W - 80, CAPTION_H)
    f = load_font(size)
    cap_line_h = f.getbbox("Ag")[3] - f.getbbox("Ag")[1] + 6
    total_h = cap_line_h * len(lines)
    ty = bar_top + (CAPTION_H - total_h) // 2
    for ln in lines:
        bbox = draw.textbbox((0, 0), ln, font=f)
        tw = bbox[2] - bbox[0]
        tx = (CANVAS_W - tw) // 2
        draw.text((tx, ty), ln, font=f, fill=CAPTION_FG)
        ty += cap_line_h

    return img


def main() -> None:
    global CANVAS_H, CAPTION_H

    frames_dir_ctx = tempfile.TemporaryDirectory(prefix="demo_gif_frames_")
    frames_dir = Path(frames_dir_ctx.name)

    # Measure every beat's body content against a scratch canvas (only the
    # width matters for wrapping) to find the tallest one, then size the
    # real canvas to fit it plus consistent padding -- one canvas size for
    # every frame, sized to the content instead of a fixed guess.
    scratch = Image.new("RGB", (CANVAS_W, 10), BG)
    scratch_draw = ImageDraw.Draw(scratch, "RGBA")
    max_content_bottom = max(
        layout_body(scratch_draw, beat, draw_it=False) for beat in BEATS
    )
    non_caption_height = max_content_bottom + 2 * PAD  # breathing room before the caption bar

    # Also measure how tall the caption bar needs to be to hold the longest
    # caption at its natural (unshrunk) font size, so a short beat can't
    # force every caption down to an illegibly small font. Probe with a huge
    # bound so wrap_words reports the natural (unshrunk) wrap.
    needed_caption_height = 0
    for beat in BEATS:
        lines, size = wrap_words(scratch_draw, beat["caption"], FONT_CAPTION, CANVAS_W - 80, 10_000)
        f = load_font(size)
        line_h = f.getbbox("Ag")[3] - f.getbbox("Ag")[1] + 6
        needed_caption_height = max(needed_caption_height, line_h * len(lines) + 16)

    # Caption bar height is whatever the longest caption actually needs at a
    # legible font (never shrunk to fit an arbitrary fixed-fraction bar).
    # The overall canvas is then content + caption, so the caption still
    # scales consistently with the frame instead of being a magic constant.
    CAPTION_H = needed_caption_height
    CANVAS_H = non_caption_height + CAPTION_H
    CANVAS_H = int(CANVAS_H)
    CAPTION_H = int(CAPTION_H)
    print(
        f"Canvas sized to {CANVAS_W}x{CANVAS_H} "
        f"(caption bar {CAPTION_H}px, {CAPTION_H / CANVAS_H:.0%} of frame)"
    )

    frames = []
    for i, beat in enumerate(BEATS, start=1):
        frame = render_frame(beat)
        frame_path = frames_dir / f"frame_{i:02d}.png"
        frame.save(frame_path)
        frames.append(frame)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    quantized = [f.convert("P", palette=Image.ADAPTIVE, colors=128) for f in frames]
    quantized[0].save(
        OUT_PATH,
        save_all=True,
        append_images=quantized[1:],
        duration=3800,
        loop=0,
        optimize=True,
    )
    size = OUT_PATH.stat().st_size
    print(f"Wrote {OUT_PATH} ({size} bytes, {len(frames)} frames)")


if __name__ == "__main__":
    main()
