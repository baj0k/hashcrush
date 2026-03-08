"""Flask routes to handle utils"""
import os
import secrets
import hashlib
import re
import shlex
import tempfile
from datetime import datetime
import _md5
from flask import current_app, has_app_context
from hashcrush.models import db
from hashcrush.models import Rules, Wordlists, Hashfiles, HashfileHashes, Hashes, Tasks, Jobs, JobTasks
from werkzeug.utils import secure_filename

_PLAINTEXT_HEX_PATTERN = re.compile(r'^[0-9a-f]+$')
DEFAULT_HASHFILE_MAX_LINE_LENGTH = 50_000
DEFAULT_HASHFILE_MAX_TOTAL_LINES = 1_000_000
DEFAULT_HASHFILE_MAX_TOTAL_BYTES = 1024 * 1024 * 1024


def _get_hashfile_validation_limit(config_key: str, default: int, minimum: int = 1) -> int:
    if not has_app_context():
        return default
    value = current_app.config.get(config_key, default)
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if parsed < minimum:
        return default
    return parsed


def _iter_hashfile_lines(hashfile_path: str):
    max_line_length = _get_hashfile_validation_limit(
        'HASHFILE_MAX_LINE_LENGTH',
        DEFAULT_HASHFILE_MAX_LINE_LENGTH,
    )
    max_total_bytes = _get_hashfile_validation_limit(
        'HASHFILE_MAX_TOTAL_BYTES',
        DEFAULT_HASHFILE_MAX_TOTAL_BYTES,
    )
    max_total_lines = _get_hashfile_validation_limit(
        'HASHFILE_MAX_TOTAL_LINES',
        DEFAULT_HASHFILE_MAX_TOTAL_LINES,
    )

    total_bytes = 0
    with open(hashfile_path, 'rb') as file:
        for line_number, raw_line in enumerate(file, start=1):
            if line_number > max_total_lines:
                raise ValueError(
                    f'Error: Hashfile has too many lines ({line_number:,}). '
                    f'Max lines is {max_total_lines:,}.'
                )
            total_bytes += len(raw_line)
            if total_bytes > max_total_bytes:
                raise ValueError(
                    f'Error: Hashfile is too large ({total_bytes:,} bytes). '
                    f'Max size is {max_total_bytes:,} bytes.'
                )
            if len(raw_line) > max_line_length:
                raise ValueError(
                    'Error line '
                    + str(line_number)
                    + ' is too long. Line length: '
                    + str(len(raw_line))
                    + '. Max length is '
                    + f'{max_line_length:,}'
                    + ' chars.'
                )

            yield line_number, raw_line.decode('utf-8', errors='replace')


def get_runtime_root_path() -> str:
    """Return absolute runtime root path for ephemeral task artifacts."""
    configured = current_app.config.get('RUNTIME_PATH')
    if configured:
        return os.path.abspath(os.path.expanduser(str(configured)))
    # Backward-compatible fallback when config does not define runtime_path.
    return os.path.join(tempfile.gettempdir(), 'hashcrush-runtime')


def get_runtime_subdir(name: str) -> str:
    """Return absolute path to a runtime subdirectory."""
    return os.path.join(get_runtime_root_path(), name)


def is_plaintext_hex_encoded(value: str | None) -> bool:
    """Return True when value matches canonical lowercase hex encoding."""
    if value is None:
        return False
    if value == '':
        return True
    if len(value) % 2 != 0:
        return False
    return bool(_PLAINTEXT_HEX_PATTERN.fullmatch(value))


def encode_plaintext_for_storage(value: str | None) -> str | None:
    """Encode plaintext to canonical lowercase hex for DB storage."""
    if value is None:
        return None
    if value == '':
        return ''
    return value.encode('latin-1').hex()


def decode_plaintext_from_storage(value: str | None) -> str | None:
    """Decode canonical plaintext storage format, with legacy fallback."""
    if value is None:
        return None
    if value == '':
        return ''
    if is_plaintext_hex_encoded(value):
        try:
            return bytes.fromhex(value).decode('latin-1')
        except (TypeError, ValueError):
            return value
    # Legacy rows stored raw plaintext; return unchanged.
    return value


def migrate_plaintext_storage_rows(batch_size: int = 1000) -> int:
    """Convert legacy raw plaintext rows to canonical hex encoding."""
    migrated_rows = 0
    last_id = 0

    while True:
        rows = (
            Hashes.query.filter(Hashes.id > last_id)
            .filter(Hashes.cracked.is_(True))
            .filter(Hashes.plaintext.isnot(None))
            .order_by(Hashes.id.asc())
            .limit(batch_size)
            .all()
        )
        if not rows:
            break

        changed = False
        for row in rows:
            last_id = row.id
            if is_plaintext_hex_encoded(row.plaintext):
                continue
            row.plaintext = encode_plaintext_for_storage(row.plaintext)
            migrated_rows += 1
            changed = True

        if changed:
            db.session.commit()

    return migrated_rows


def _resolve_storage_path(stored_path: str) -> str:
    """Resolve a DB-stored path to an absolute filesystem path.

    HashCrush historically stored paths like 'hashcrush/control/...'. Under systemd,
    the process CWD may not be the project root, so we resolve relative paths
    against both the Flask package root and the project root.
    """
    if not stored_path:
        return stored_path
    if os.path.isabs(stored_path):
        return stored_path

    normalized = stored_path.replace('\\', '/')
    package_root = os.path.abspath(current_app.root_path)
    project_root = os.path.abspath(os.path.join(package_root, os.pardir))

    candidates = [
        os.path.join(project_root, normalized),
        os.path.join(package_root, normalized),
    ]

    if normalized.startswith('hashcrush/'):
        stripped = normalized[len('hashcrush/'):]
        candidates.extend([
            os.path.join(package_root, stripped),
            os.path.join(project_root, stripped),
        ])

    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate

    # Default to project-root-relative for 'hashcrush/...', otherwise package-root-relative.
    return os.path.join(project_root, normalized) if normalized.startswith('hashcrush/') else os.path.join(package_root, normalized)



def save_file(path, form_file):
    """Function to safe file from form submission"""

    random_hex = secrets.token_hex(8)
    original_name = secure_filename(os.path.basename(form_file.filename or 'upload.txt')) or 'upload.txt'
    file_name = f'{random_hex}_{original_name}'
    target_dir = path if os.path.isabs(path) else os.path.join(current_app.root_path, path)
    os.makedirs(target_dir, exist_ok=True)
    file_path = os.path.join(target_dir, file_name)
    form_file.save(file_path)
    return file_path

def _count_generator(reader):
    b = reader(1024 * 1024)
    while b:
        yield b
        b = reader(1024 * 1024)

def get_linecount(filepath):
    """Function to return line count of file"""

    with open(filepath, 'rb') as fp:
        c_generator = _count_generator(fp.raw.read)
        count = sum(buffer.count(b'\n') for buffer in c_generator)
        return count + 1

def get_filehash(filepath):
    """Function to sha256 hash of file"""

    sha256_hash = hashlib.sha256()
    with open(filepath,"rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def get_md5_hash(string):
    """Function to get md5 hash of string"""

    m = _md5.md5(string.encode('utf-8'))
    return m.hexdigest()

def import_hash_only(line, hash_type):
    """Function to import single hash"""

    hash = Hashes.query.filter_by(hash_type=hash_type, sub_ciphertext=get_md5_hash(line)).first()

    if hash:
        return hash.id

    new_hash = Hashes(hash_type=hash_type, sub_ciphertext=get_md5_hash(line), ciphertext=line, cracked=0)
    db.session.add(new_hash)
    db.session.flush()
    return new_hash.id

def import_hashfilehashes(hashfile_id, hashfile_path, file_type, hash_type):
    """Function to hashfile"""

    with open(hashfile_path, 'r') as file:
        for line in file:
            # If line is empty:
            if len(line) > 0:
                if file_type == 'hash_only':
                    # forcing lower casing of hash as hashcat will return lower cased version of the has and we want to match what we imported.
                    if hash_type in ('300', '1731'):
                        hash_id = import_hash_only(line=line.lower().rstrip(), hash_type=hash_type)
                    elif hash_type == '2100':
                        line = line.lower().rstrip()
                        line = line.replace('$dcc2$', '$DCC2$')
                        hash_id = import_hash_only(line, hash_type)
                    else:
                        hash_id = import_hash_only(line=line.rstrip(), hash_type=hash_type)
                    # extract username from dcc2 hash
                    if hash_type == '2100':
                        username = line.split('#')[1]
                    else:
                        username = None
                elif file_type == 'user_hash':
                    if ':' in line:
                        if hash_type in ('300', '1731'):
                            hash_id = import_hash_only(line=line.lower().rstrip(), hash_type=hash_type)
                        if hash_type == '2100':
                            line = line.split(':',1)[1].rstrip()
                            line = line.lower()
                            line = line.replace('$dcc2$', '$DCC2$')
                            hash_id = import_hash_only(line, hash_type)
                            username = line.split(':')[0]
                        else:
                            hash_id = import_hash_only(line=line.split(':',1)[1].rstrip(), hash_type=hash_type)
                            username = line.split(':')[0]
                    else:
                        db.session.rollback()
                        return False
                elif file_type == 'shadow':
                    hash_id= import_hash_only(line=line.split(':')[1], hash_type=hash_type)
                    username = line.split(':')[0]
                elif file_type == 'pwdump':
                    # do we let user select LM so that we crack those instead of NTLM?
                    # First extracting usernames so we can filter out machine accounts
                    if re.search(r"\$$", line.split(':')[0]):
                    #if '$' in line.split(':')[0]:
                        continue
                    else:
                        hash_id = import_hash_only(line=line.split(':')[3].lower(), hash_type='1000')
                        username = line.split(':')[0]
                elif file_type == 'kerberos':
                    hash_id = import_hash_only(line=line.lower().rstrip(), hash_type=hash_type)
                    if hash_type == '18200':
                        username = line.split('$')[3].split(':')[0]
                    else:
                        username = line.split('$')[3]
                elif file_type == 'NetNTLM':
                    # First extracting usernames so we can filter out machine accounts
                    # 5600, domain is case sensitve. Hashcat returns username in upper case.
                    if re.search(r"\$$", line.split(':')[0]):
                    #if '$' in line.split(':')[0]:
                        continue
                    else:
                        # uppercase uesrname in line
                        line_list = line.split(':')
                        # uppercase the username in line
                        line_list[0] = line_list[0].upper()
                        # lowercase the rest (except domain name) 3,4,5
                        line_list[3] = line_list[3].lower()
                        line_list[4] = line_list[4].lower()
                        line_list[5] = line_list[5].lower()
                        line = ':'.join(line_list)
                        hash_id = import_hash_only(line=line.rstrip(), hash_type=hash_type)
                        username = line.split(':', maxsplit=1)[0]
                else:
                    db.session.rollback()
                    return False
                if username is None:
                    hashfilehashes = HashfileHashes(hash_id=hash_id, hashfile_id=hashfile_id)
                else:
                    hashfilehashes = HashfileHashes(hash_id=hash_id, username=username.encode('latin-1').hex(), hashfile_id=hashfile_id)
                db.session.add(hashfilehashes)

    db.session.commit()
    return True

def update_dynamic_wordlist(wordlist_id, requesting_user_id: int | None = None, include_all: bool = False):
    """Function to update dynamic wordlist"""

    wordlist = Wordlists.query.get(wordlist_id)
    if not wordlist:
        return False

    plaintext_query = (
        db.session.query(Hashes.plaintext)
        .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
        .join(Hashfiles, HashfileHashes.hashfile_id == Hashfiles.id)
        .filter(Hashes.cracked.is_(True))
        .filter(Hashes.plaintext.isnot(None))
    )
    if not include_all:
        owner_scope = requesting_user_id if requesting_user_id is not None else wordlist.owner_id
        plaintext_query = plaintext_query.filter(Hashfiles.owner_id == owner_scope)

    plaintext_rows = plaintext_query.distinct().all()

    # Do we delete the original file, or overwrite it?
    # if we overwrite, what happens if the new content has fewer lines than the previous file.
    # would this even happen? In most/all cases there will be new stuff to add.
    # is there a file lock on a wordlist when in use by hashcat? Could we just create a temp file and replace after generation?
    resolved_path = _resolve_storage_path(wordlist.path)
    os.makedirs(os.path.dirname(resolved_path), exist_ok=True)

    with open(resolved_path, 'wt') as file:
        for entry in plaintext_rows:
            decoded_plaintext = decode_plaintext_from_storage(entry.plaintext)
            if decoded_plaintext is not None:
                file.write(decoded_plaintext + '\n')

    # update line count
    wordlist.size = get_linecount(resolved_path)
    # update file hash
    wordlist.checksum = get_filehash(resolved_path)
    # update last update
    wordlist.last_updated = datetime.today()
    db.session.commit()
    return True

def build_hashcat_argv(job_id, task_id, hashcat_bin=None):
    """Build a safe argv list for launching hashcat without a shell."""

    task = Tasks.query.get(task_id)
    job = Jobs.query.get(job_id)
    if not task or not job:
        raise ValueError("Invalid job/task combination when building hashcat command.")

    hashfilehashes_single_entry = HashfileHashes.query.filter_by(hashfile_id=job.hashfile_id).first()
    if not hashfilehashes_single_entry:
        raise ValueError("Job has no hashes assigned.")

    hashes_single_entry = Hashes.query.get(hashfilehashes_single_entry.hash_id)
    if not hashes_single_entry:
        raise ValueError("Hash type could not be determined from job hashfile.")

    hash_type = hashes_single_entry.hash_type
    attackmode = task.hc_attackmode
    mask = task.hc_mask
    rules_file = Rules.query.get(task.rule_id) if task.rule_id else None
    wordlist = Wordlists.query.get(task.wl_id) if task.wl_id else None

    hashes_dir = get_runtime_subdir('hashes')
    outfiles_dir = get_runtime_subdir('outfiles')
    os.makedirs(hashes_dir, exist_ok=True)
    os.makedirs(outfiles_dir, exist_ok=True)

    target_file = os.path.join(hashes_dir, f'hashfile_{job.id}_{task.id}.txt')
    crack_file = os.path.join(outfiles_dir, f'hc_cracked_{job.id}_{task.id}.txt')
    session = f'job{job.id}_task{task.id}'
    hashcat_bin_path = hashcat_bin or current_app.config.get('HASHCAT_BIN', 'hashcat')
    try:
        status_timer = int(current_app.config.get('HASHCAT_STATUS_TIMER', 5))
    except (TypeError, ValueError):
        status_timer = 5
    status_timer = max(1, status_timer)

    common = [
        hashcat_bin_path,
        '-O',
        '-w', '3',
        '--session', session,
        '-m', str(hash_type),
        '--potfile-disable',
        '--status',
        '--status-timer', str(status_timer),
        '--outfile-format', '1,3',
        '--outfile', crack_file,
    ]

    if attackmode == 'combinator':
        raise ValueError("Task attack mode 'combinator' is not supported yet. Edit the task and choose 'dictionary', 'maskmode', or 'bruteforce'.")
    if attackmode == 'bruteforce':
        return common + ['-a', '3', target_file]
    if attackmode == 'maskmode':
        if not mask:
            raise ValueError("Task attack mode 'maskmode' requires a hashcat mask.")
        return common + ['-a', '3', target_file, mask]
    if attackmode == 'dictionary':
        if not wordlist:
            raise ValueError("Task attack mode 'dictionary' requires a wordlist.")
        wordlist_path = _resolve_storage_path(wordlist.path)
        if not os.path.exists(wordlist_path):
            raise ValueError(f"Wordlist file is missing: {wordlist_path}")
        cmd = list(common)
        if rules_file:
            rules_path = _resolve_storage_path(rules_file.path)
            if not os.path.exists(rules_path):
                raise ValueError(f"Rule file is missing: {rules_path}")
            cmd.extend(['-r', rules_path])
        cmd.extend([target_file, wordlist_path])
        return cmd

    raise ValueError(f"Unsupported task attack mode: {attackmode}")


def build_hashcat_command(job_id, task_id):
    """Build a shell-quoted hashcat command string for display and persistence."""
    argv = build_hashcat_argv(job_id=job_id, task_id=task_id)
    return ' '.join(shlex.quote(arg) for arg in argv)

def update_job_task_status(jobtask_id, status):
    """Update the status of a JobTask and cascade changes to its Job.

    Notes:
      - Job completion is determined by the absence of active tasks (Queued/Running/Importing/Paused).
    """

    jobtask = JobTasks.query.get(jobtask_id)
    if jobtask is None:
        return False

    jobtask.status = status
    if status in ('Completed', 'Canceled', 'Paused'):
        jobtask.worker_pid = None

    db.session.commit()

    # Update the parent Job's lifecycle.
    job = Jobs.query.get(jobtask.job_id)
    if not job:
        return True

    # If we just started a task, transition the job to Running (if it was queued/paused).
    if status in ('Running', 'Importing') and job.status in ('Queued', 'Paused'):
        job.status = 'Running'
        if not job.started_at:
            job.started_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        db.session.commit()

    # Paused task means this job is no longer actively cracking.
    if status == 'Paused' and job.status != 'Paused':
        job.status = 'Paused'
        db.session.commit()

    # Determine if all tasks are finished.
    active_statuses = {'Queued', 'Running', 'Importing', 'Paused'}
    remaining_active = JobTasks.query.filter(
        JobTasks.job_id == job.id,
        JobTasks.status.in_(active_statuses),
    ).count()

    if remaining_active == 0 and job.status in ('Queued', 'Running', 'Paused'):
        # Mark job as completed or canceled depending on whether any task was canceled.
        any_canceled = JobTasks.query.filter(
            JobTasks.job_id == job.id,
            JobTasks.status == 'Canceled',
        ).count() > 0

        job.status = 'Canceled' if any_canceled else 'Completed'
        job.ended_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        db.session.commit()
        current_app.logger.info(
            'Job lifecycle update: job_id=%s name="%s" finished with status=%s',
            job.id,
            job.name,
            job.status,
        )

        # Update hashfile runtime if we have a start/end time.
        try:
            start_time = datetime.strptime(str(job.started_at), '%Y-%m-%d %H:%M:%S')
            end_time = datetime.strptime(str(job.ended_at), '%Y-%m-%d %H:%M:%S')
            duration = abs(end_time - start_time).seconds
        except Exception:
            duration = 0

        if duration and job.hashfile_id:
            hashfile = Hashfiles.query.get(job.hashfile_id)
            if hashfile:
                hashfile.runtime += duration
                db.session.commit()

    elif remaining_active > 0:
        # Keep the parent job status consistent with remaining active tasks.
        has_running = JobTasks.query.filter(
            JobTasks.job_id == job.id,
            JobTasks.status.in_(('Running', 'Importing')),
        ).count() > 0
        has_paused = JobTasks.query.filter(
            JobTasks.job_id == job.id,
            JobTasks.status == 'Paused',
        ).count() > 0
        has_queued = JobTasks.query.filter(
            JobTasks.job_id == job.id,
            JobTasks.status == 'Queued',
        ).count() > 0

        if has_running and job.status != 'Running':
            job.status = 'Running'
            db.session.commit()
        elif not has_running and has_paused and job.status != 'Paused':
            job.status = 'Paused'
            db.session.commit()
        elif not has_running and not has_paused and has_queued and job.status != 'Queued':
            job.status = 'Queued'
            db.session.commit()

    return True

def validate_pwdump_hashfile(hashfile_path, hash_type):
    """Function to validate if hashfile submitted is a pwdump format"""

    try:
        for line_number, line in _iter_hashfile_lines(hashfile_path):
            line = line.rstrip('\r\n')
            if len(line) == 0:
                continue
            if ':' not in line:
                return 'Error line ' + str(line_number) + ' is missing a : character. Pwdump file should include usernames.'
            colon_cnt = line.count(':')
            if colon_cnt < 6:
                return 'Error line ' + str(line_number) + '. File does not appear to be be in a pwdump format.'
            if hash_type == '1000':
                line_parts = line.split(':')
                if len(line_parts) < 4 or len(line_parts[3]) != 32:
                    return 'Error line ' + str(line_number) + ' has an invalid number of characters (' + str(len(line.rstrip())) + ') should be 32'
            else:
                return 'Sorry. The only Hash Type we support for PWDump files is NTLM'
    except ValueError as error:
        return str(error)
    return False

def validate_netntlm_hashfile(hashfile_path):
    """Function to validate if hashfile submitted is a netntlm format"""

    list_of_username_and_computers = set()
    try:
        for line_number, line in _iter_hashfile_lines(hashfile_path):
            line = line.rstrip('\r\n')
            if len(line) == 0:
                continue
            if ':' not in line:
                return 'Error line ' + str(line_number) + ' is missing a : character. NetNTLM file should include usernames.'
            colon_cnt = line.count(':')
            if colon_cnt < 5:
                return 'Error line ' + str(line_number) + '. File does not appear to be be in a NetNTLM format.'

            line_parts = line.split(':')
            username_computer = (line_parts[0] + ':' + line_parts[2]).lower()
            if username_computer in list_of_username_and_computers:
                return 'Error: Duplicate usernames / computer found in hashfiles (' + str(username_computer) + '). Please only submit unique usernames / computer.'
            list_of_username_and_computers.add(username_computer)
    except ValueError as error:
        return str(error)
    return False

def validate_kerberos_hashfile(hashfile_path, hash_type):
    """Function to validate if hashfile submitted is a kerberos format"""
    try:
        for line_number, line in _iter_hashfile_lines(hashfile_path):
            line = line.rstrip('\r\n')
            if len(line) == 0:
                continue
            if '$' not in line:
                return 'Error line ' + str(line_number) + ' is missing a $ character. kerberos file should include these.'
            dollar_cnt = line.count('$')
            line_parts = line.split('$')

            if hash_type == '7500':
                if dollar_cnt != 6:
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Kerberos 5, etype 23, AS-REQ Pre-Auth (1)'
                if line_parts[1] != 'krb5pa':
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Kerberos 5, etype 23, AS-REQ Pre-Auth (2)'
                if line_parts[2] != '23':
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Kerberos 5, etype 23, AS-REQ Pre-Auth (3)'
            elif hash_type == '13100':
                if dollar_cnt != 7 and dollar_cnt != 8:
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Kerberos 5, etype 23, TGS-REP (1)'
                if line_parts[1] != 'krb5tgs':
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Kerberos 5, etype 23, TGS-REP (2)'
                if line_parts[2] != '23':
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Kerberos 5, etype 23, TGS-REP (3)'
            elif hash_type == '18200':
                if dollar_cnt != 4 and dollar_cnt != 5:
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Kerberos 5, etype 23, AS-REP (1)'
                if line_parts[1] != 'krb5asrep':
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Kerberos 5, etype 23, AS-REP (2)'
                if line_parts[2] != '23':
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Kerberos 5, etype 23, AS-REP (3)'
            elif hash_type == '19600':
                if dollar_cnt != 6 and dollar_cnt != 7:
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Kerberos 5, etype 17, TGS-REP (AES128-CTS-HMAC-SHA1-96) (1)'
                if line_parts[1] != 'krb5tgs':
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Kerberos 5, etype 17, TGS-REP (AES128-CTS-HMAC-SHA1-96) (2)'
                if line_parts[2] != '17':
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Kerberos 5, etype 17, TGS-REP (AES128-CTS-HMAC-SHA1-96) (3)'
            elif hash_type == '19700':
                if dollar_cnt != 6 and dollar_cnt != 7:
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Kerberos 5, etype 18, TGS-REP (AES256-CTS-HMAC-SHA1-96) (1)'
                if line_parts[1] != 'krb5tgs':
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Kerberos 5, etype 18, TGS-REP (AES256-CTS-HMAC-SHA1-96) (2)'
                if line_parts[2] != '18':
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Kerberos 5, etype 18, TGS-REP (AES256-CTS-HMAC-SHA1-96) (3)'
            elif hash_type == '19800':
                if dollar_cnt != 5 and dollar_cnt != 6:
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Kerberos 5, etype 17, Pre-Auth (1)'
                if line_parts[1] != 'krb5pa':
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Kerberos 5, etype 17, Pre-Auth (2)'
                if line_parts[2] != '17':
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Kerberos 5, etype 17, Pre-Auth (3)'
            elif hash_type == '19900':
                if dollar_cnt != 5 and dollar_cnt != 6:
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Kerberos 5, etype 18, Pre-Auth (1)'
                if line_parts[1] != 'krb5pa':
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Kerberos 5, etype 18, Pre-Auth (2)'
                if line_parts[2] != '18':
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Kerberos 5, etype 18, Pre-Auth (3)'
            else:
                return 'Sorry. The only suppported Hash Types are: 7500, 13100, 18200, 19600, 19700, 19800 and 19900.'
    except ValueError as error:
        return str(error)
    return False

def validate_shadow_hashfile(hashfile_path, hash_type):
    """Function to validate if hashfile submitted is a shadow format"""
    try:
        for line_number, line in _iter_hashfile_lines(hashfile_path):
            line = line.rstrip('\r\n')
            if len(line) == 0:
                continue
            if ':' not in line:
                return 'Error line ' + str(line_number) + ' is missing a : character. shadow file should include usernames.'
            if hash_type == '1800':
                dollar_cnt = line.count('$')
                if dollar_cnt != 3:
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Sha512 Crypt from a shadow file.'
                if '$6$' not in line:
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Sha512 Crypt from a shadow file.'
    except ValueError as error:
        return str(error)
    return False

def validate_user_hash_hashfile(hashfile_path):
    """Function to validate if hashfile submitted is a user:hash format"""
    try:
        for line_number, line in _iter_hashfile_lines(hashfile_path):
            line = line.rstrip('\r\n')
            if len(line) == 0:
                continue
            if ':' not in line:
                return 'Error line ' + str(line_number) + ' is missing a : character. user:hash file should have just ONE of these'
    except ValueError as error:
        return str(error)

    return False

# Dumb way of doing this, we return with an error message if we have an issue with the hashfile
# and return false if hashfile is okay. :/ Should be the otherway around :shrug emoji:
def validate_hash_only_hashfile(hashfile_path, hash_type):
    """Function to validate if hashfile submitted is a hash only format"""

    try:
        for line_number, line in _iter_hashfile_lines(hashfile_path):
            line = line.rstrip('\r\n')
            if len(line) == 0:
                continue

            # Check hash types
            if hash_type in ('0', '22', '1000'):
                if len(line.rstrip()) != 32:
                    return 'Error line ' + str(line_number) + ' has an invalid number of characters (' + str(len(line.rstrip())) + ') should be 32'
            if hash_type == '122':
                if len(line.rstrip()) != 50:
                    return 'Error line ' + str(line_number) + ' has an invalid number of characters (' + str(len(line.rstrip())) + ') should be 50'
            if hash_type == '300':
                if len(line.rstrip()) != 40:
                    return 'Error line ' + str(line_number) + ' has an invalid number of characters (' + str(len(line.rstrip())) + ') should be 40'
            if hash_type == '500':
                if '$1$' not in line:
                    return 'Error line ' + str(line_number) + ' is not a valid md5Crypt, MD5 (Unix) or Cisco-IOS $1$ (MD5) hash'
            if hash_type == '1100':
                if ':' not in line:
                    return 'Error line ' + str(line_number) + ' is missing a : character. Domain Cached Credentials (DCC), MS Cache hashes should have one'
            if hash_type == '1800':
                dollar_cnt = line.count('$')
                if dollar_cnt != 3:
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Sha512 Crypt.'
                if '$6$' not in line:
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Sha512 Crypt.'
            if hash_type == '2100':
                if '$' not in line:
                    return 'Error line ' + str(line_number) + ' is missing a $ character. DCC2 Hashes should have these'
                dollar_cnt = line.count('$')
                hash_cnt = line.count('#')
                if dollar_cnt != 2:
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: DCC2 MS Cache'
                if hash_cnt != 2:
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: DCC2 MS Cache'
            if hash_type == '2400':
                if len(line.rstrip()) != 18:
                    return 'Error line ' + str(line_number) + ' has an invalid number of characters (' + str(len(line.rstrip())) + ') should be 18'
            if hash_type == '2410':
                if ':' not in line:
                    return 'Error line ' + str(line_number) + ' is missing a : character. Cisco-ASA Hashes should have these.'
            if hash_type == '3200':
                if '$' not in line:
                    return 'Error line ' + str(line_number) + ' is missing a $ character. bcrypt Hashes should have these.'
                dollar_cnt = line.count('$')
                if dollar_cnt != 3:
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: bcrypt'
            if hash_type == '5700':
                if len(line.rstrip()) != 43:
                    return 'Error line ' + str(line_number) + ' has an invalid number of characters (' + str(len(line.rstrip())) + ') should be 43'
            if hash_type == '7100':
                if '$' not in line:
                    return 'Error line ' + str(line_number) + ' is missing a $ character. Mac OSX 10.8+ ($ml$) hashes should have these.'
                dollar_cnt = line.count('$')
                if dollar_cnt != 2:
                    return 'Error line ' + str(line_number) + '. Doesnt appear to be of the type: Mac OSX 10.8+ ($ml$)'
            if hash_type in ('9400', '9500', '9600'):
                if '$' not in line:
                    return 'Error line ' + str(line_number) + ' is missing a $ character. Office hashes require 2.'
                if '*' not in line:
                    return 'Error line ' + str(line_number) + ' is missing a * character. Office hashes require 6.'
                star_cnt = line.count('*')
                if star_cnt != 7:
                    return 'Error line ' + str(line_number) + '. Does not appear to be of the type office.'
    except ValueError as error:
        return str(error)

    return False

def getTimeFormat(total_runtime): # Runtime in seconds
    """Function to convert seconds into, minutes, hours, days or weeks"""

    if total_runtime >= 604800:
        return str(round(total_runtime/604800)) + " week(s)"
    elif total_runtime >= 86400:
        return str(round(total_runtime/86400)) + " day(s)"
    elif total_runtime >= 3600:
        return str(round(total_runtime/3600)) + " hour(s)"
    elif total_runtime >= 60:
        return str(round(total_runtime/60)) + " minute(s)"
    elif total_runtime < 60:
        return "less then 1 minute"
