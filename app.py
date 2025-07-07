import os
import uuid
import hashlib
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from db import get_db, close_db, init_db_command
import secrets

# --- Flask App Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
MAX_QUOTA_BYTES = 500 * 1024 * 1024 #500 Mo

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- Register DB helpers ---
app.teardown_appcontext(close_db)
app.cli.add_command(init_db_command)

# --- File Security Functions ---
def generate_unique_filename(original_filename):
    """Generate a unique filename using UUID and preserve original extension."""
    safe_filename = secure_filename(original_filename)
    
    _, file_extension = os.path.splitext(safe_filename)
    
    unique_id = str(uuid.uuid4())
    
    unique_filename = f"{unique_id}{file_extension}"
    
    return unique_filename, safe_filename

def get_file_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def is_allowed_file(filename):
    """Check if file type is allowed."""
    ALLOWED_EXTENSIONS = {
        'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg',
        'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'mp3', 'wav', 'flac', 'aac', 'ogg',
        'mp4', 'avi', 'mov', 'wmv', 'flv',
        'zip', 'rar', '7z', 'tar', 'gz'
    }
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Routes ---

@app.route('/')
def index():    
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('mainpage'))

# --- Main Page ---
@app.route('/mainpage')
def mainpage():
    return render_template('mainpage.html')

# --- Registration ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    db = get_db()
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not username or not email or not password:
            flash('Tous les champs sont obligatoires.', 'error')
            return render_template('register.html')
        
        hashed_password = generate_password_hash(password)
        
        try:
            db.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (username, email, hashed_password)
            )
            db.commit()
            flash('Inscription réussie! Vous pouvez maintenant vous connecter.', 'success')
            return redirect(url_for('login'))
        except db.IntegrityError:
            flash('Email ou nom d\'utilisateur déjà utilisé.', 'error')
            return render_template('register.html')
        except Exception as e:
            flash("Erreur inattendue lors de l'inscription.", 'error')
            return render_template('register.html')
    
    return render_template('register.html')


# --- Login ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    db = get_db()
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Nom d\'utilisateur et mot de passe requis.', 'error')
            return render_template('login.html')
        
        try:
            user = db.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()
            
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                flash('Connexion réussie!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Identifiants invalides.', 'error')
                return render_template('login.html')
        except Exception as e:
            flash("Erreur inattendue lors de la connexion.", 'error')
            return render_template('login.html')
    
    return render_template('login.html')

# --- Logout ---
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('mainpage'))

# --- Dashboard (File List & Upload) ---
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    user_id = session['user_id']

    result = db.execute("SELECT SUM(file_size) AS total FROM files WHERE user_id = ? AND delete_date = 'NULL'",(user_id,)).fetchone()
    used_space = result["total"] if result["total"] else 0

    if request.method == 'POST':
        try:
            file = request.files['file']
            if file and file.filename:
                file.seek(0, os.SEEK_END)
                file_size_new = file.tell()
                file.seek(0)

                if used_space + file_size_new > MAX_QUOTA_BYTES:
                    flash(f"Quota dépassé : vous avez utilisé {round(used_space / (1024*1024),1)} Mo sur 500 Mo. Veuillez supprimer des fichiers avant de téléverser.", "error")
                    return redirect(url_for('dashboard'))
                if not is_allowed_file(file.filename):
                    flash('Type de fichier non autorisé.', 'error')
                    return redirect(url_for('dashboard'))
                
                unique_filename, safe_original_name = generate_unique_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                
                try:
                    file.save(filepath)
                    file_hash = get_file_hash(filepath)
                    file_size = os.path.getsize(filepath)
                except Exception as e:
                    flash('Erreur lors de l\'enregistrement du fichier.', 'error')
                    return redirect(url_for('dashboard'))
                try:
                    cursor = db.execute(
                        "INSERT INTO files (user_id, filename, original_filename, file_hash, file_size, upload_date, delete_date) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (user_id, unique_filename, safe_original_name, file_hash, file_size, datetime.now().isoformat(), 'NULL')
                    )
                    db.commit()
                    file_id = cursor.lastrowid
                    db.execute(
                        "INSERT INTO history (user_id, file_id, action, timestamp) VALUES (?, ?, ?, ?)",
                        (user_id, file_id, 'upload', datetime.now().isoformat())
                    )
                    db.commit()
                    flash('Fichier téléversé avec succès!', 'success')
                except Exception as e:
                    flash('Erreur lors de l\'enregistrement en base de données.', 'error')
                    if os.path.exists(filepath):
                        os.remove(filepath)
            else:
                flash('Aucun fichier sélectionné.', 'error')
        except Exception as e:
            flash('Erreur inattendue lors du téléversement.', 'error')

    try:
        cutoff_date = datetime.now() - timedelta(seconds=30)
        
        old_files = db.execute(
            "SELECT * FROM files WHERE delete_date != 'NULL' AND delete_date < ?",
            (cutoff_date.isoformat(),)
        ).fetchall()
        
        for file in old_files:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                except Exception as e:
                    app.logger.error(f"Erreur suppression fichier {filepath}: {e}")
                    continue
            
            db.execute("DELETE FROM files WHERE id = ?", (file['id'],))
        
        db.commit()
        
    except Exception as e:
        db.rollback()
        app.logger.error(f"Erreur nettoyage corbeille: {e}")

    try:
        files = db.execute(
            "SELECT * FROM files WHERE user_id = ? AND delete_date = 'NULL' ORDER BY upload_date DESC",
            (user_id,)
        ).fetchall()
    except Exception as e:
        flash('Erreur lors de la récupération des fichiers.', 'error')
        files = []
    return render_template('dashboard.html', files=files, username=session['username'], used_space=used_space, max_quota=MAX_QUOTA_BYTES)

# --- Download File ---
@app.route('/download/<int:file_id>')
def download(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    try:
        file = db.execute(
            "SELECT * FROM files WHERE id = ? AND user_id = ?",
            (file_id, session['user_id'])
        ).fetchone()
    except Exception as e:
        flash('Erreur lors de la récupération du fichier.', 'error')
        return redirect(url_for('dashboard'))
    
    if file:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
        if os.path.exists(filepath):
            try:
                current_hash = get_file_hash(filepath)
                if current_hash != file['file_hash']:
                    flash('Erreur: Le fichier a été corrompu.', 'error')
                    return redirect(url_for('dashboard'))
                db.execute(
                    "INSERT INTO history (user_id, file_id, action, timestamp) VALUES (?, ?, ?, ?)",
                    (session['user_id'], file_id, 'download', datetime.now().isoformat())
                )
                db.commit()
                return send_from_directory(
                    app.config['UPLOAD_FOLDER'], 
                    file['filename'], 
                    as_attachment=True,
                    download_name=file['original_filename']
                )
            except Exception as e:
                flash('Erreur lors du téléchargement du fichier.', 'error')
                return redirect(url_for('dashboard'))
        else:
            flash('Fichier introuvable sur le serveur.', 'error')
            return redirect(url_for('dashboard'))
    else:
        flash('Fichier introuvable ou non autorisé.', 'error')
        return redirect(url_for('dashboard'))

# --- Delete File ---
@app.route('/delete/<int:file_id>', methods=['POST'])
def delete(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    try:
        file = db.execute(
            "SELECT * FROM files WHERE id = ? AND user_id = ?",
            (file_id, session['user_id'])
        ).fetchone()
    except Exception as e:
        flash('Erreur lors de la récupération du fichier à supprimer.', 'error')
        return redirect(url_for('dashboard'))
    
    if file:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
        try:
            db.execute("UPDATE files SET delete_date = ? WHERE id = ? AND user_id = ?", (datetime.now().isoformat(), file_id, session['user_id']))
            db.commit()
            db.execute(
                "INSERT INTO history (user_id, file_id, action, timestamp) VALUES (?, ?, ?, ?)",
                (session['user_id'], file_id, 'delete', datetime.now().isoformat())
            )
            db.commit()
            flash('Fichier supprimé avec succès.', 'success')
        except Exception as e:
            flash('Erreur lors de la suppression en base de données.', 'error')
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except Exception as e:
            flash('Erreur lors de la suppression du fichier sur le disque.', 'error')
            return redirect(url_for('dashboard'))
    else:
        flash('Fichier introuvable ou non autorisé.', 'error')
    return redirect(url_for('dashboard'))

# --- Trash Page ---
@app.route('/trash')
def trash():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    try:
        # Récupérer les fichiers supprimés (avec delete_date non NULL)
        deleted_files = db.execute(
            "SELECT * FROM files WHERE user_id = ? AND delete_date != 'NULL' ORDER BY delete_date DESC",
            (session['user_id'],)
        ).fetchall()
    except Exception as e:
        flash('Erreur lors de la récupération des fichiers supprimés.', 'error')
        deleted_files = []
    
    return render_template('trash.html', deleted_files=deleted_files, username=session['username'])

# --- Restore File ---
@app.route('/restore/<int:file_id>', methods=['POST'])
def restore(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    try:
        # Vérifier que le fichier appartient bien à l'utilisateur
        file = db.execute(
            "SELECT * FROM files WHERE id = ? AND user_id = ? AND delete_date != 'NULL'",
            (file_id, session['user_id'])
        ).fetchone()
        
        if file:
            # Restaurer le fichier (mettre delete_date à NULL)
            db.execute(
                "UPDATE files SET delete_date = 'NULL' WHERE id = ?",
                (file_id,)
            )
            db.commit()
            db.execute(
                "INSERT INTO history (user_id, file_id, action, timestamp) VALUES (?, ?, ?, ?)",
                (session['user_id'], file_id, 'restore', datetime.now().isoformat())
            )
            db.commit()
            flash('Fichier restauré avec succès.', 'success')
        else:
            flash('Fichier introuvable ou non autorisé.', 'error')
    except Exception as e:
        flash('Erreur lors de la restauration du fichier.', 'error')
    
    return redirect(url_for('trash'))

# --- Permanent Delete ---
@app.route('/permanent_delete/<int:file_id>', methods=['POST'])
def permanent_delete(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    try:
        # Vérifier que le fichier appartient bien à l'utilisateur
        file = db.execute(
            "SELECT * FROM files WHERE id = ? AND user_id = ? AND delete_date != 'NULL'",
            (file_id, session['user_id'])
        ).fetchone()
        
        if file:
            # Supprimer physiquement le fichier
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
            if os.path.exists(filepath):
                os.remove(filepath)
            # Supprimer l'entrée en base de données
            db.execute("DELETE FROM files WHERE id = ?", (file_id,))
            db.commit()
            # Log permanent delete in history
            db.execute(
                "INSERT INTO history (user_id, file_id, action, timestamp) VALUES (?, ?, ?, ?)",
                (session['user_id'], file_id, 'permanent_delete', datetime.now().isoformat())
            )
            db.commit()
            flash('Fichier supprimé définitivement.', 'success')
        else:
            flash('Fichier introuvable ou non autorisé.', 'error')
    except Exception as e:
        flash('Erreur lors de la suppression définitive.', 'error')
    
    return redirect(url_for('trash'))

# --- History Page ---
@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    try:
        history_entries = db.execute("""
            SELECT h.*, f.original_filename 
            FROM history h 
            LEFT JOIN files f ON h.file_id = f.id 
            WHERE h.user_id = ? 
            ORDER BY h.timestamp DESC 
            LIMIT 50
        """, (session['user_id'],)).fetchall()
        
        return render_template('history.html', history_entries=history_entries, username=session['username'])
        
    except Exception as e:
        flash('Erreur lors de la récupération de l\'historique.', 'error')
        return redirect(url_for('dashboard'))

# --- File Sharing Functions ---
def generate_share_token():
    """Generate a secure random token for file sharing."""
    return secrets.token_urlsafe(32)

def create_share_link(file_id, user_id, expiration_days=7):
    """Create a new share link for a file."""
    db = get_db()
    share_token = generate_share_token()
    created_at = datetime.now().isoformat()
    expires_at = (datetime.now() + timedelta(days=expiration_days)).isoformat()
    
    try:
        db.execute(
            "INSERT INTO share_links (file_id, share_token, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            (file_id, share_token, user_id, created_at, expires_at)
        )
        db.commit()
        return share_token
    except Exception as e:
        db.rollback()
        raise e

# --- Create Share Link ---
@app.route('/share/<int:file_id>', methods=['POST'])
def share_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    try:
        file = db.execute(
            "SELECT * FROM files WHERE id = ? AND user_id = ? AND delete_date = 'NULL'",
            (file_id, session['user_id'])
        ).fetchone()
        
        if not file:
            flash('Fichier introuvable ou non autorisé.', 'error')
            return redirect(url_for('dashboard'))
        
        existing_share = db.execute(
            "SELECT * FROM share_links WHERE file_id = ? AND is_active = 1",
            (file_id,)
        ).fetchone()
        
        if existing_share:
            share_url = request.host_url.rstrip('/') + url_for('shared_file', token=existing_share['share_token'])
            db.execute(
                "INSERT INTO history (user_id, file_id, action, timestamp) VALUES (?, ?, ?, ?)",
                (session['user_id'], file_id, 'share', datetime.now().isoformat())
            )
            db.commit()
            return jsonify({
                'success': True,
                'share_url': share_url,
                'message': 'Lien de partage existant récupéré.'
            })
        
        share_token = create_share_link(file_id, session['user_id'])
        share_url = request.host_url.rstrip('/') + url_for('shared_file', token=share_token)
        db.execute(
            "INSERT INTO history (user_id, file_id, action, timestamp) VALUES (?, ?, ?, ?)",
            (session['user_id'], file_id, 'share', datetime.now().isoformat())
        )
        db.commit()
        return jsonify({
            'success': True,
            'share_url': share_url,
            'message': 'Lien de partage créé avec succès!'
        })
        
    except Exception as e:
        flash('Erreur lors de la création du lien de partage.', 'error')
        return jsonify({'success': False, 'message': 'Erreur lors de la création du lien de partage.'})

# --- Access Shared File ---
@app.route('/shared/<token>')
def shared_file(token):
    db = get_db()
    try:
        share_link = db.execute(
            "SELECT * FROM share_links WHERE share_token = ? AND is_active = 1",
            (token,)
        ).fetchone()
        
        if not share_link:
            flash('Lien de partage invalide ou expiré.', 'error')
            return redirect(url_for('mainpage'))
        
        if share_link['expires_at']:
            expires_at = datetime.fromisoformat(share_link['expires_at'])
            if datetime.now() > expires_at:
                flash('Ce lien de partage a expiré.', 'error')
                return redirect(url_for('mainpage'))
        
        file = db.execute(
            "SELECT * FROM files WHERE id = ? AND delete_date = 'NULL'",
            (share_link['file_id'],)
        ).fetchone()
        
        if not file:
            flash('Fichier introuvable ou supprimé.', 'error')
            return redirect(url_for('mainpage'))
        
        db.execute(
            "UPDATE share_links SET download_count = download_count + 1 WHERE id = ?",
            (share_link['id'],)
        )
        db.commit()
        
        return render_template('shared_file.html', file=file, share_link=share_link)
        
    except Exception as e:
        flash('Erreur lors de l\'accès au fichier partagé.', 'error')
        return redirect(url_for('mainpage'))

# --- Download Shared File ---
@app.route('/shared/<token>/download')
def download_shared_file(token):
    db = get_db()
    try:
        share_link = db.execute(
            "SELECT * FROM share_links WHERE share_token = ? AND is_active = 1",
            (token,)
        ).fetchone()
        
        if not share_link:
            flash('Lien de partage invalide ou expiré.', 'error')
            return redirect(url_for('mainpage'))
        
        if share_link['expires_at']:
            expires_at = datetime.fromisoformat(share_link['expires_at'])
            if datetime.now() > expires_at:
                flash('Ce lien de partage a expiré.', 'error')
                return redirect(url_for('mainpage'))
        
        file = db.execute(
            "SELECT * FROM files WHERE id = ? AND delete_date = 'NULL'",
            (share_link['file_id'],)
        ).fetchone()
        
        if not file:
            flash('Fichier introuvable ou supprimé.', 'error')
            return redirect(url_for('mainpage'))
        
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
        if os.path.exists(filepath):
            try:
                current_hash = get_file_hash(filepath)
                if current_hash != file['file_hash']:
                    flash('Erreur: Le fichier a été corrompu.', 'error')
                    return redirect(url_for('shared_file', token=token))
                
                return send_from_directory(
                    app.config['UPLOAD_FOLDER'], 
                    file['filename'], 
                    as_attachment=True,
                    download_name=file['original_filename']
                )
            except Exception as e:
                flash('Erreur lors du téléchargement du fichier.', 'error')
                return redirect(url_for('shared_file', token=token))
        else:
            flash('Fichier introuvable sur le serveur.', 'error')
            return redirect(url_for('shared_file', token=token))
            
    except Exception as e:
        flash('Erreur lors du téléchargement du fichier partagé.', 'error')
        return redirect(url_for('mainpage'))

# --- Manage Share Links ---
@app.route('/manage_shares')
def manage_shares():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    try:
        share_links = db.execute("""
            SELECT sl.*, f.original_filename, f.file_size, f.upload_date
            FROM share_links sl
            JOIN files f ON sl.file_id = f.id
            WHERE sl.created_by = ? AND sl.is_active = 1
            ORDER BY sl.created_at DESC
        """, (session['user_id'],)).fetchall()
        
        return render_template('manage_shares.html', share_links=share_links, username=session['username'])
        
    except Exception as e:
        flash('Erreur lors de la récupération des liens de partage.', 'error')
        return redirect(url_for('dashboard'))

# --- Deactivate Share Link ---
@app.route('/deactivate_share/<int:share_id>', methods=['POST'])
def deactivate_share(share_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    try:
        share_link = db.execute(
            "SELECT * FROM share_links WHERE id = ? AND created_by = ?",
            (share_id, session['user_id'])
        ).fetchone()
        
        if share_link:
            db.execute(
                "UPDATE share_links SET is_active = 0 WHERE id = ?",
                (share_id,)
            )
            db.commit()
            flash('Lien de partage désactivé avec succès.', 'success')
        else:
            flash('Lien de partage introuvable ou non autorisé.', 'error')
            
    except Exception as e:
        flash('Erreur lors de la désactivation du lien de partage.', 'error')
    
    return redirect(url_for('manage_shares'))

# --- Run App ---
if __name__ == '__main__':
    app.run(debug=True)
