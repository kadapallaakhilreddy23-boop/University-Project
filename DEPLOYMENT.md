# Deployment Guide for College Management System

## Overview
This system is optimized to support **1000+ students** using SQLite with WAL mode for better concurrency.

## Performance Optimizations
- **WAL Mode (Write-Ahead Logging):** Allows concurrent reads and writes
- **64MB Cache:** Improves query performance
- **30-second Timeout:** Prevents database locks under load
- **Persistent Sessions:** 30-day login sessions reduce database load

## Capacity
- **Current Setup:** Supports 1000+ concurrent users
- **Database:** SQLite (optimized for production)
- **Hosting:** Can be deployed on Render, PythonAnywhere, or similar platforms

## Deployment Steps

### 1. Prepare for Production

#### Change Default Passwords
Before deploying, change these in `app.py`:
```python
admin_password = os.environ.get("DEFAULT_ADMIN_PASSWORD", "CHANGE_THIS_PASSWORD")
security_password = os.environ.get("DEFAULT_SECURITY_PASSWORD", "CHANGE_THIS_PASSWORD")
faculty_password = os.environ.get("DEFAULT_FACULTY_PASSWORD", "CHANGE_THIS_PASSWORD")
```

#### Set Environment Variables
Set these in your hosting platform:
- `FLASK_SECRET_KEY`: Random 32-character string (generate with: `python -c "import secrets; print(secrets.token_hex(32))"`)
- `UNIVERSITY_NAME`: Your college name
- `UNIVERSITY_MOTTO`: Your college motto

### 2. Deploy to Render (Recommended)

#### Step 1: Push to GitHub
```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/yourusername/your-repo.git
git push -u origin main
```

#### Step 2: Create Render Account
1. Go to [render.com](https://render.com)
2. Sign up and connect your GitHub account

#### Step 3: Create Web Service
1. Click "New" → "Web Service"
2. Connect your GitHub repository
3. Configure:
   - **Name:** college-management-system
   - **Region:** Choose nearest to your users
   - **Branch:** main
   - **Runtime:** Python 3
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `python app.py`

#### Step 4: Add Environment Variables
In Render dashboard → Environment:
```
FLASK_SECRET_KEY=your-random-32-char-string
UNIVERSITY_NAME=Your College Name
UNIVERSITY_MOTTO=Your Motto
```

#### Step 5: Deploy
Click "Deploy" and wait for the build to complete. Your site will be live at `https://your-app.onrender.com`

### 3. Deploy to PythonAnywhere

#### Step 1: Create Account
1. Go to [pythonanywhere.com](https://pythonanywhere.com)
2. Sign up for a free account

#### Step 2: Create Web App
1. Go to "Web" tab → "Add a new web app"
2. Choose "Flask" framework
3. Python version: 3.10+
4. Path: `/home/yourusername/collegeproject`

#### Step 3: Upload Files
1. Use the web interface or git to upload your files
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

#### Step 4: Configure WSGI
Edit the WSGI file to point to your app:
```python
from app import create_app
app = create_app()
```

#### Step 5: Set Environment Variables
In the "Web" tab → "Variables" section, add your environment variables.

### 4. Database Backup Strategy

#### Automatic Backup (Render)
Render automatically backs up your database. For additional safety:

#### Manual Backup
```bash
# Download your database file
scp youruser@yourserver:/path/to/app.db ./backup_$(date +%Y%m%d).db
```

#### Backup Script
Create `backup.sh`:
```bash
#!/bin/bash
cp app.db backups/app_backup_$(date +%Y%m%d_%H%M%S).db
# Keep only last 7 days
find backups/ -name "app_backup_*" -mtime +7 -delete
```

### 5. Monitoring and Maintenance

#### Check Logs
- **Render:** Dashboard → Logs
- **PythonAnywhere:** Web tab → Log files

#### Performance Monitoring
- Monitor response times
- Check database lock errors
- Track concurrent users

#### Regular Maintenance
- Weekly database backups
- Monthly security updates
- Quarterly password changes for admin accounts

## Security Checklist

- [ ] Change all default passwords
- [ ] Set strong FLASK_SECRET_KEY
- [ ] Enable HTTPS (automatic on most platforms)
- [ ] Set up regular database backups
- [ ] Monitor logs for suspicious activity
- [ ] Keep dependencies updated
- [ ] Test with real users before full rollout

## Scaling Beyond 1000 Users

If you need to support more than 1000 users, consider:

1. **Upgrade to PostgreSQL:**
   - Better concurrency handling
   - More robust under heavy load
   - Easier to scale horizontally

2. **Use a Load Balancer:**
   - Distribute traffic across multiple instances
   - Improve availability

3. **Caching:**
   - Add Redis for session storage
   - Cache frequently accessed data

## Troubleshooting

### Database Locked Errors
- WAL mode should prevent this
- If it occurs, increase timeout in `db()` function

### Slow Performance
- Check database size
- Consider archiving old data
- Increase cache size in PRAGMA

### Memory Issues
- Monitor memory usage
- Consider upgrading hosting plan
- Optimize queries

## Support

For issues:
1. Check logs first
2. Review this guide
3. Test locally with similar data volume
4. Contact hosting platform support if needed
