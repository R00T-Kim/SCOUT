# SCOUT Design System

Firmware security analysis tool design system inspired by **Linear** (precision dark-mode engineering) and **Sentry** (security-tool purple aesthetic).

## 1. Visual Theme & Atmosphere

SCOUT uses a dark-mode-native design built on deep purple-black backgrounds. The aesthetic evokes late-night security research: a near-black canvas where vulnerability data emerges through carefully calibrated luminance hierarchy. Purple-violet accents signal interactive elements, while a subtle lime-green highlight draws attention to critical findings.

**Key Characteristics:**
- Dark purple-black backgrounds (`#150f23`, `#1a1330`) -- never pure black
- Indigo-violet accent (`#7170ff`) for interactive elements and brand identity
- IPC purple (`#c084fc`) for inter-process communication visualizations
- Lime-green highlight (`#c2ef4e`) for high-visibility alerts (sparingly)
- Semi-transparent white borders (`rgba(255,255,255,0.05)` to `rgba(255,255,255,0.10)`)
- Glassmorphism with `backdrop-filter: blur(18px) saturate(180%)`
- Inter Variable as primary typeface, Berkeley Mono for code

## 2. Color Palette & Roles

### Background Surfaces
| Token | Value | Usage |
|-------|-------|-------|
| `--bg` | `#150f23` | Primary page background |
| `--bg-secondary` | `#1a1330` | Panel, sidebar, KPI bar |
| `--surface` | `rgba(255,255,255,0.05)` | Card backgrounds, inputs |
| `--surface-hover` | `rgba(255,255,255,0.08)` | Hover states |
| `--glass` | `rgba(255,255,255,0.06)` | Glassmorphic panels |
| `--glass-border` | `rgba(255,255,255,0.10)` | Glass element borders |

### Text & Content
| Token | Value | Usage |
|-------|-------|-------|
| `--ink` | `#f7f8f8` | Primary text (not pure white) |
| `--ink-secondary` | `#d0d6e0` | Body text, descriptions |
| `--muted` | `#8a8f98` | Placeholders, metadata, labels |

### Brand & Accent
| Token | Value | Usage |
|-------|-------|-------|
| `--accent` | `#7170ff` | Primary interactive color, links, CTAs |
| `--accent-glow` | `rgba(113,112,255,0.15)` | Focus rings, active sidebar |
| `--info` | `#6a5fc1` | Secondary purple, informational |
| `--ipc-purple` | `#c084fc` | IPC channel visualization |
| `--lime` | `#c2ef4e` | High-visibility highlight (use sparingly) |

### Status Colors
| Token | Value | Usage |
|-------|-------|-------|
| `--success` | `#27a644` | Pass, verified, ok |
| `--warning` | `#fbbf24` | Partial, blocked, caution |
| `--danger` | `#f87171` | Failed, critical, high severity |

### Border & Line
| Token | Value | Usage |
|-------|-------|-------|
| `--line` | `rgba(255,255,255,0.05)` | Subtle dividers |
| Border default | `rgba(255,255,255,0.08)` | Card borders |
| Border subtle | `rgba(255,255,255,0.05)` | Minimal structure |

### Light Theme Overrides
| Token | Value |
|-------|-------|
| `--bg` | `#f7f8f8` |
| `--bg-secondary` | `#ffffff` |
| `--ink` | `#0f172a` |
| `--accent` | `#5e6ad2` |
| `--muted` | `#62666d` |

## 3. Typography Rules

### Font Families
- **Primary**: `Inter Variable`, `Inter`, system-ui, -apple-system, `Segoe UI`, Helvetica, Arial, sans-serif
- **Monospace**: `Berkeley Mono`, `SF Mono`, `Cascadia Code`, `Fira Code`, `JetBrains Mono`, Consolas, monospace

### Hierarchy
| Role | Size | Weight | Letter Spacing | Usage |
|------|------|--------|----------------|-------|
| Logo | 1.1rem | 700 | 0.15em | Top bar brand |
| KPI Value | 1.4rem | 700 | normal | Dashboard numbers |
| Stat Value | 2.2rem | 800 | normal | Large stat cards |
| Card Title | 0.75rem | 700 | 0.12em | Section headers (uppercase) |
| Card Subtitle | 0.85rem | 600 | normal | Sub-section headings |
| Body | 14px (0.875rem) | 400 | normal | Default reading text |
| Meta | 0.85rem | 400 | normal | Secondary content |
| Label | 0.68rem | 600-700 | 0.08em | KPI labels, stat labels (uppercase) |
| Code | 0.82rem | 400 | normal | Code blocks, monospace |
| Micro | 0.72rem | 400 | normal | Timestamps, annotations |

### Principles
- Uppercase + letter-spacing for labels, badges, and section headers
- `text-transform: uppercase` with `letter-spacing: 0.08em-0.12em` is the systematic label pattern
- Primary text is `#f7f8f8`, never pure `#ffffff` to prevent eye strain
- Line height: 1.6 for body, 1.1-1.2 for large numbers

## 4. Component Stylings

### Cards (Glassmorphic)
```css
background: rgba(255,255,255,0.04);
border: 1px solid rgba(255,255,255,0.08);
border-radius: 12px;
backdrop-filter: blur(18px) saturate(180%);
box-shadow: 0 8px 32px rgba(0,0,0,0.3);
```
- Hover: background `0.07`, border `0.15`, `translateY(-1px)`
- Top shine: 1px gradient `linear-gradient(90deg, transparent, rgba(255,255,255,0.15), transparent)`

### Buttons & Controls
```css
background: var(--surface);
border: 1px solid var(--glass-border);
border-radius: 6px;
color: var(--ink);
transition: all 0.2s ease;
```
- Hover: accent glow background, accent border and text color
- Active: `var(--accent)` background, white text

### Badges (Pill)
```css
border-radius: 9999px;
font-size: 0.68rem;
font-weight: 700;
letter-spacing: 0.04em;
text-transform: uppercase;
padding: 3px 10px;
```
- Pass: green-tinted (`rgba(39,166,68,0.20)`, color `#27a644`)
- Fail: red-tinted (`rgba(248,113,113,0.20)`, color `#f87171`)
- Blocked: yellow-tinted
- IPC: purple-tinted (`rgba(168,85,247,0.12)`, color `#c084fc`)

### Stat Cards
```css
background: rgba(255,255,255,0.06);
border: 1px solid rgba(255,255,255,0.12);
border-radius: 8px;
padding: 20px;
text-align: center;
```

### Filter Chips
```css
border-radius: 9999px;
font-size: 0.75rem;
border: 1px solid var(--glass-border);
background: var(--surface);
```
- Active: accent background, white text

### Tables
- Header: uppercase, `0.68rem`, weight 700, muted color
- Rows: `0.82rem`, hover background `rgba(255,255,255,0.03)`
- Borders: ultra-subtle `rgba(255,255,255,0.03)`

## 5. Layout Principles

### Spacing
- Base unit: 8px
- Scale: 4px, 8px, 12px, 16px, 20px, 24px, 32px, 40px
- Card body padding: 20px
- Card header padding: 16px 24px

### Grid
- Max content width: 1800px
- Sidebar: 200px fixed
- Main content: flex
- Stat grid: `repeat(auto-fit, minmax(140px, 1fr))`

### Border Radius Scale
| Size | Value | Usage |
|------|-------|-------|
| Small | 6px | Buttons, inputs, code blocks |
| Standard | 8px | Stat cards, table wraps |
| Card | 12px | Main cards, modals, search |
| Pill | 9999px | Badges, filter chips, progress bars |

## 6. Depth & Elevation

| Level | Treatment | Usage |
|-------|-----------|-------|
| Flat | No shadow | Page background |
| Surface | `rgba(255,255,255,0.05)` bg + border | Cards, inputs |
| Elevated | `0 8px 32px rgba(0,0,0,0.3)` | Cards default |
| Prominent | `0 12px 48px rgba(0,0,0,0.4)` | Card hover, floating |
| Dialog | `0 24px 80px rgba(0,0,0,0.4)` | Modals |
| Ambient | Purple-tinted radial gradients | Background atmosphere |

Shadow philosophy: On dark purple surfaces, elevation is communicated through background luminance stepping (`0.04` -> `0.06` -> `0.08`) combined with semi-transparent borders rather than traditional shadows.

## 7. CLI / TUI Design

### ANSI Color Mapping
| Element | Code | Color | Usage |
|---------|------|-------|-------|
| Header | `\x1b[1m\x1b[35m` | Bold Magenta | "SCOUT :: {path}" |
| Section titles | `\x1b[1m\x1b[35m` | Bold Magenta | "Status", "Exploit Candidate Map" |
| Success/Verified | `\x1b[1m\x1b[32m` | Bold Green | Verified verdicts |
| Warning | `\x1b[1m\x1b[33m` | Bold Yellow | Partial, not_attempted |
| Danger/Failed | `\x1b[1m\x1b[31m` | Bold Red | Failed verdicts, high severity |
| Dividers | `\x1b[2m` | Dim | Horizontal rules |
| Metadata | `\x1b[34m` | Blue | Secondary info |
| Dim text | `\x1b[2m` | Dim | De-emphasized content |

### Extended Colors (256-color terminals)
| Element | Code | Approximate | Usage |
|---------|------|-------------|-------|
| Brand accent | `\x1b[38;5;141m` | Soft violet | Brand highlights |
| Deep purple | `\x1b[38;5;98m` | Deep purple | Secondary accent |
| Lime highlight | `\x1b[38;5;149m` | Lime green | Critical attention |

### TUI Layout
- Header: `SCOUT :: {run_dir}` in bold magenta
- Section divider: 96x horizontal rule (`---` or `───`)
- Two-column interactive: left 52% (candidate list), right (details)
- Evidence badges: `D`, `E`, `V`, `C`, `S` inline
- Priority tags: `H` (red), `M` (yellow), `L` (green)
- Vim-style navigation: j/k, g/G, q to quit

## 8. Do's and Don'ts

### Do
- Use deep purple-black backgrounds (`#150f23`, `#1a1330`) -- never pure black
- Apply `text-transform: uppercase` with `letter-spacing` on labels and badges
- Use semi-transparent white borders, never solid dark borders on dark backgrounds
- Reserve `#7170ff` (accent) for interactive elements only
- Use `#f7f8f8` for primary text, not pure `#ffffff`
- Apply glassmorphism with `blur(18px) saturate(180%)` for layered panels
- Use lime green (`#c2ef4e`) sparingly -- once per section maximum
- Communicate elevation through background luminance stepping

### Don't
- Don't use pure black (`#000000`) for backgrounds
- Don't use gray borders -- use purple-tinted semi-transparent whites
- Don't apply accent color decoratively -- it's reserved for interaction
- Don't use sharp corners (0px radius) -- minimum 6px for all elements
- Don't mix lime-green with IPC purple in the same component
- Don't use weight 700+ except for stat values and logos

## 9. Agent Prompt Guide

### Quick Color Reference
- Background: `#150f23` (primary), `#1a1330` (secondary)
- Text: `#f7f8f8` (primary), `#d0d6e0` (secondary), `#8a8f98` (muted)
- Accent: `#7170ff` (interactive), `#6a5fc1` (info), `#c084fc` (IPC)
- Status: `#27a644` (success), `#fbbf24` (warning), `#f87171` (danger)
- Highlight: `#c2ef4e` (lime, sparingly)
- Border: `rgba(255,255,255,0.08)` default, `rgba(255,255,255,0.05)` subtle

### Example Prompts
- "Create a card on `#150f23` background: `rgba(255,255,255,0.04)` bg, `1px solid rgba(255,255,255,0.08)` border, 12px radius, `backdrop-filter: blur(18px) saturate(180%)`. Title at 0.75rem Inter weight 700 uppercase `letter-spacing: 0.12em`, color `#d0d6e0`."
- "Build a stat card: `rgba(255,255,255,0.06)` bg, 8px radius, large number at 2.2rem weight 800 `#f7f8f8`, label at 0.68rem weight 600 uppercase `#8a8f98`."
- "Design a badge pill: 9999px radius, 0.68rem weight 700 uppercase, `letter-spacing: 0.04em`. Pass variant: `rgba(39,166,68,0.20)` bg, `#27a644` text, `1px solid rgba(39,166,68,0.35)` border."
