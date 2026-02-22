# UI Update Guide

## What Was Changed

All three pages have been updated to match the new **HPD Security Dashboard** design:

### 1. **Dashboard** (`dashboard.html`)
- ✅ New dark theme with gradient background
- ✅ Modern card-based layout
- ✅ Interactive charts (Chart.js)
- ✅ Attack calendar visualization
- ✅ World map and country list
- ✅ Real-time statistics
- ✅ Consistent color scheme

### 2. **Login Page** (`login.html`)
- ✅ Matches dashboard design
- ✅ Dark theme (#0f172a background)
- ✅ Same gradient background
- ✅ Consistent styling
- ✅ Modern form inputs

### 3. **Attackers Page** (`attackers.html`)
- ✅ Matches dashboard design
- ✅ Dark theme consistency
- ✅ Same color scheme
- ✅ Modern cards and badges
- ✅ Consistent typography

## Design System

### Colors
- **Background**: `#0f172a` (dark slate)
- **Cards**: `#1e293b` (slate)
- **Primary**: `#60a5fa` (blue)
- **Success**: `#22c55e` (green)
- **Warning**: `#f59e0b` (amber)
- **Danger**: `#ef4444` (red)
- **Text**: `#cbd5e1` (light slate)

### Typography
- **Font**: Inter (Google Fonts)
- **Weights**: 400, 500, 600, 700

### Background
- **Gradient**: `linear-gradient(135deg, #dbeafe, #e9d5ff)`
- Light blue to purple gradient

## Applying Changes

### Option 1: Rebuild Container (Recommended)
```bash
docker-compose stop web-dashboard
docker-compose build --no-cache web-dashboard
docker-compose up -d web-dashboard
```

### Option 2: Restart Container
```bash
docker-compose restart web-dashboard
```

### Option 3: Full Rebuild
```bash
docker-compose down
docker-compose build web-dashboard
docker-compose up -d
```

## Verifying Changes

1. **Clear Browser Cache**
   - Press `Ctrl+Shift+R` (Windows/Linux) or `Cmd+Shift+R` (Mac)
   - Or use incognito/private mode

2. **Check Dashboard**
   - Go to `http://localhost:5000`
   - Should see new dark theme with gradient background
   - Login page should match

3. **Check Attackers Page**
   - Click "🎯 Attackers" tab
   - Should see consistent dark theme

## Troubleshooting

### Still Seeing Old UI?

1. **Hard Refresh Browser**
   ```bash
   # Windows/Linux: Ctrl+Shift+R
   # Mac: Cmd+Shift+R
   ```

2. **Check Container Logs**
   ```bash
   docker-compose logs web-dashboard
   ```

3. **Verify Files Updated**
   ```bash
   # Check if files exist
   ls -la monitoring/web-dashboard/templates/
   ```

4. **Rebuild Without Cache**
   ```bash
   docker-compose build --no-cache web-dashboard
   docker-compose up -d web-dashboard
   ```

5. **Check Browser Console**
   - Press F12
   - Look for errors in Console tab
   - Check Network tab for failed requests

### Container Not Starting?

1. **Check Docker Status**
   ```bash
   docker ps
   docker-compose ps
   ```

2. **View Error Logs**
   ```bash
   docker-compose logs web-dashboard
   ```

3. **Check Port Availability**
   ```bash
   netstat -an | grep 5000
   ```

## Features in New UI

### Dashboard
- ✅ Real-time statistics cards
- ✅ Session overview chart (24-hour timeline)
- ✅ Attack calendar (30-day view)
- ✅ Attack data (Today/Week/Month)
- ✅ Attack ratio chart (doughnut)
- ✅ World map visualization
- ✅ Country list (top 10)
- ✅ Recent sessions list

### Login
- ✅ Dark theme matching dashboard
- ✅ Modern form design
- ✅ Security warnings
- ✅ Smooth animations

### Attackers
- ✅ Consistent dark theme
- ✅ Location information cards
- ✅ Attack type badges
- ✅ Severity indicators
- ✅ Statistics grid
- ✅ Session list

## Browser Compatibility

- ✅ Chrome/Edge (latest)
- ✅ Firefox (latest)
- ✅ Safari (latest)
- ✅ Mobile browsers

## Next Steps

After applying changes:
1. Clear browser cache
2. Access `http://localhost:5000`
3. Login with: `admin` / `honeypot2024`
4. Explore new dashboard features

All pages now have a consistent, modern design! 🎨
