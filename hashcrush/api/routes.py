"""HTTP API routes for authenticated user automation."""

import gzip
import json
import ntpath
import os
import secrets
import shutil
from io import BytesIO

from flask import Blueprint, current_app, jsonify, redirect, request, send_file
from sqlalchemy.ext.declarative import DeclarativeMeta

from hashcrush.models import Hashes, HashfileHashes, Jobs, JobTasks, Rules, Tasks, Users, Wordlists, db
from hashcrush.utils.utils import update_dynamic_wordlist


api = Blueprint("api", __name__)


def _candidate_paths_from_db_path(db_path: str | None, filename: str, kind: str, config_key: str | None = None):
    """Generate candidate absolute/relative paths for a control file."""
    candidates: list[str] = []
    if db_path:
        candidates.append(db_path)
        candidates.append(db_path.replace("\\", "/"))

        if not os.path.isabs(db_path):
            candidates.append(os.path.join(current_app.root_path, db_path))
            candidates.append(os.path.join(current_app.root_path, db_path.replace("\\", "/")))

            normalized = db_path.replace("\\", "/")
            if normalized.startswith("hashcrush/"):
                candidates.append(os.path.join(current_app.root_path, normalized[len("hashcrush/") :]))

            project_root = os.path.abspath(os.path.join(current_app.root_path, os.pardir))
            candidates.append(os.path.join(project_root, db_path))
            candidates.append(os.path.join(project_root, db_path.replace("\\", "/")))

    configured_root = None
    if config_key:
        configured_value = current_app.config.get(config_key)
        if configured_value:
            configured_root = os.path.abspath(os.path.expanduser(str(configured_value)))

    if configured_root:
        if db_path and not os.path.isabs(db_path):
            candidates.append(os.path.join(configured_root, db_path))
            candidates.append(os.path.join(configured_root, db_path.replace("\\", "/")))
        candidates.append(os.path.join(configured_root, filename))

    candidates.append(os.path.join(current_app.root_path, "control", kind, filename))
    candidates.append(os.path.join(os.path.abspath(os.path.join(current_app.root_path, os.pardir)), "control", kind, filename))
    candidates.append(os.path.join("hashcrush", "control", kind, filename))
    candidates.append(os.path.join("control", kind, filename))

    seen: set[str] = set()
    unique: list[str] = []
    for path in candidates:
        if path and path not in seen:
            seen.add(path)
            unique.append(path)
    return unique


class AlchemyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj.__class__, DeclarativeMeta):
            fields = {}
            for field in [x for x in dir(obj) if not x.startswith("_") and x != "metadata"]:
                data = obj.__getattribute__(field)
                try:
                    json.dumps(data)
                    fields[field] = data
                except TypeError:
                    fields[field] = None
            return fields
        return json.JSONEncoder.default(self, obj)


def _get_api_key(req) -> str | None:
    return req.headers.get("X-API-Key")


def _get_request_user(req):
    api_key = _get_api_key(req)
    if not api_key:
        return None
    return Users.query.filter_by(api_key=api_key).first()


def _is_user_authorized(req) -> bool:
    return _get_request_user(req) is not None


def _is_job_visible_to_user(job: Jobs | None, user: Users | None) -> bool:
    if not job or not user:
        return False
    return bool(user.admin or job.owner_id == user.id)


def _is_task_visible_to_user(task: Tasks | None, user: Users | None) -> bool:
    if not task or not user:
        return False
    return bool(user.admin or task.owner_id == user.id)


def _is_hashfile_visible_to_user(hashfile_id: int, user: Users | None) -> bool:
    from hashcrush.models import Hashfiles

    hashfile = Hashfiles.query.get(hashfile_id)
    if not hashfile or not user:
        return False
    return bool(user.admin or hashfile.owner_id == user.id)


@api.route("/v1/not_authorized", methods=["GET", "POST"])
def v1_api_unauthorized():
    message = {
        "status": 403,
        "type": "Error",
        "msg": "Your API key is not authorized for this action.",
    }
    return jsonify(message), 403


@api.route("/v1/rules", methods=["GET"])
def v1_api_get_rules():
    if not _is_user_authorized(request):
        return redirect("/v1/not_authorized")

    user = _get_request_user(request)
    if user.admin:
        rules = Rules.query.all()
    else:
        rules = Rules.query.filter_by(owner_id=user.id).all()
    message = {"status": 200, "rules": json.dumps(rules, cls=AlchemyEncoder)}
    return jsonify(message)


@api.route("/v1/rules/<int:rules_id>", methods=["GET"])
def v1_api_get_rules_download(rules_id):
    if not _is_user_authorized(request):
        return redirect("/v1/not_authorized")

    user = _get_request_user(request)
    rules = Rules.query.get(rules_id)
    if not rules:
        return jsonify({"status": 404, "type": "message", "msg": "Rule not found"}), 404
    if not user.admin and rules.owner_id != user.id:
        return jsonify({"status": 403, "type": "Error", "msg": "Forbidden"}), 403

    raw_rules_path = getattr(rules, "path", None)
    rules_name = ntpath.basename(raw_rules_path) if raw_rules_path else None
    if not rules_name:
        return jsonify({"status": 404, "type": "message", "msg": "Rule file missing"}), 404

    src_candidates = _candidate_paths_from_db_path(
        raw_rules_path,
        rules_name,
        "rules",
        config_key="RULES_PATH",
    )
    src_path = next((p for p in src_candidates if p and os.path.exists(p)), None)
    if not src_path:
        return jsonify({"status": 404, "type": "message", "msg": "Rule file missing"}), 404

    gz_buf = BytesIO()
    with open(src_path, "rb") as f_in:
        with gzip.GzipFile(filename=rules_name, mode="wb", compresslevel=9, fileobj=gz_buf) as gz_out:
            shutil.copyfileobj(f_in, gz_out)
    gz_buf.seek(0)
    return send_file(gz_buf, mimetype="application/octet-stream", download_name=f"{rules_name}.gz")


@api.route("/v1/wordlists", methods=["GET"])
def v1_api_get_wordlist():
    if not _is_user_authorized(request):
        return redirect("/v1/not_authorized")

    user = _get_request_user(request)
    if user.admin:
        wordlists = Wordlists.query.all()
    else:
        wordlists = Wordlists.query.filter_by(owner_id=user.id).all()
    message = {"status": 200, "wordlists": json.dumps(wordlists, cls=AlchemyEncoder)}
    return jsonify(message)


@api.route("/v1/wordlists/<int:wordlist_id>", methods=["GET"])
def v1_api_get_wordlist_download(wordlist_id):
    if not _is_user_authorized(request):
        return redirect("/v1/not_authorized")

    user = _get_request_user(request)
    wordlist = Wordlists.query.get(wordlist_id)
    if not wordlist:
        return jsonify({"status": 404, "type": "message", "msg": "Wordlist not found"}), 404
    if not user.admin and wordlist.owner_id != user.id:
        return jsonify({"status": 403, "type": "Error", "msg": "Forbidden"}), 403

    raw_wordlist_path = getattr(wordlist, "path", None)
    wordlist_name = ntpath.basename(raw_wordlist_path) if raw_wordlist_path else None
    if not wordlist_name:
        return jsonify({"status": 404, "type": "message", "msg": "Wordlist file missing"}), 404

    src_candidates = _candidate_paths_from_db_path(
        raw_wordlist_path,
        wordlist_name,
        "wordlists",
        config_key="WORDLISTS_PATH",
    )
    src_path = next((p for p in src_candidates if p and os.path.exists(p)), None)
    if not src_path and getattr(wordlist, "type", None) == "dynamic":
        try:
            update_dynamic_wordlist(wordlist_id)
        except Exception:
            current_app.logger.exception("Failed to generate dynamic wordlist id=%s", wordlist_id)
        src_candidates = _candidate_paths_from_db_path(
            raw_wordlist_path,
            wordlist_name,
            "wordlists",
            config_key="WORDLISTS_PATH",
        )
        src_path = next((p for p in src_candidates if p and os.path.exists(p)), None)

    if not src_path:
        return jsonify({"status": 404, "type": "message", "msg": "Wordlist file missing"}), 404

    gz_buf = BytesIO()
    with open(src_path, "rb") as f_in:
        with gzip.GzipFile(filename=wordlist_name, mode="wb", compresslevel=9, fileobj=gz_buf) as gz_out:
            shutil.copyfileobj(f_in, gz_out)
    gz_buf.seek(0)
    return send_file(gz_buf, mimetype="application/octet-stream", download_name=f"{wordlist_name}.gz")


@api.route("/v1/updateWordlist/<int:wordlist_id>", methods=["GET"])
def v1_api_get_update_wordlist(wordlist_id):
    if not _is_user_authorized(request):
        return redirect("/v1/not_authorized")

    user = _get_request_user(request)
    wordlist = Wordlists.query.get(wordlist_id)
    if not wordlist:
        return jsonify({"status": 404, "type": "Error", "msg": "Wordlist not found"}), 404
    if not user.admin and wordlist.owner_id != user.id:
        return jsonify({"status": 403, "type": "Error", "msg": "Forbidden"}), 403

    update_dynamic_wordlist(wordlist_id)
    return jsonify({"status": 200, "type": "message", "msg": "OK"})


@api.route("/v1/jobTasks/<int:job_task_id>", methods=["GET"])
def v1_api_get_queue_assignment(job_task_id):
    if not _is_user_authorized(request):
        return redirect("/v1/not_authorized")

    user = _get_request_user(request)
    job_task = JobTasks.query.get(job_task_id)
    if not job_task:
        return jsonify({"status": 404, "type": "message", "msg": "Job task not found"}), 404

    job = Jobs.query.get(job_task.job_id)
    if not _is_job_visible_to_user(job, user):
        return jsonify({"status": 403, "type": "Error", "msg": "Forbidden"}), 403

    message = {"status": 200, "job_task": json.dumps(job_task, cls=AlchemyEncoder)}
    return jsonify(message)


@api.route("/v1/jobs/<int:job_id>", methods=["GET"])
def v1_api_get_job(job_id):
    if not _is_user_authorized(request):
        return redirect("/v1/not_authorized")

    user = _get_request_user(request)
    job = Jobs.query.get(job_id)
    if not _is_job_visible_to_user(job, user):
        return jsonify({"status": 403, "type": "Error", "msg": "Forbidden"}), 403

    message = {"status": 200, "job": json.dumps(job, cls=AlchemyEncoder)}
    return jsonify(message)


@api.route("/v1/tasks/<int:task_id>", methods=["GET"])
def v1_api_get_task(task_id):
    if not _is_user_authorized(request):
        return redirect("/v1/not_authorized")

    user = _get_request_user(request)
    task = Tasks.query.get(task_id)
    if not _is_task_visible_to_user(task, user):
        return jsonify({"status": 403, "type": "Error", "msg": "Forbidden"}), 403

    message = {"status": 200, "task": json.dumps(task, cls=AlchemyEncoder)}
    return jsonify(message)


@api.route("/v1/hashfiles/<int:hashfile_id>", methods=["GET"])
def v1_api_get_hashfile(hashfile_id):
    if not _is_user_authorized(request):
        return redirect("/v1/not_authorized")

    user = _get_request_user(request)
    if not _is_hashfile_visible_to_user(hashfile_id, user):
        return jsonify({"status": 403, "type": "Error", "msg": "Forbidden"}), 403

    tmp_dir = os.path.join(current_app.root_path, "control", "tmp")
    os.makedirs(tmp_dir, exist_ok=True)

    random_hex = secrets.token_hex(8)
    tmp_file = os.path.join(tmp_dir, random_hex)
    with open(tmp_file, "w", encoding="utf-8", errors="ignore") as file_object:
        dbresults = (
            db.session.query(Hashes, HashfileHashes)
            .outerjoin(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
            .filter(Hashes.cracked.is_(False))
            .filter(HashfileHashes.hashfile_id == hashfile_id)
            .all()
        )
        for result in dbresults:
            file_object.write(result[0].ciphertext + "\n")

    return send_file(tmp_file, as_attachment=True, download_name=random_hex)


@api.route("/v1/getHashType/<int:hashfile_id>", methods=["GET"])
def v1_api_get_hash_type(hashfile_id):
    if not _is_user_authorized(request):
        return redirect("/v1/not_authorized")

    user = _get_request_user(request)
    if not _is_hashfile_visible_to_user(hashfile_id, user):
        return jsonify({"status": 403, "type": "Error", "msg": "Forbidden"}), 403

    hashfile_hash = HashfileHashes.query.filter_by(hashfile_id=hashfile_id).first()
    if not hashfile_hash:
        return jsonify({"status": 404, "type": "Error", "msg": "Hashfile has no hashes"}), 404

    hash_row = Hashes.query.get(hashfile_hash.hash_id)
    if not hash_row:
        return jsonify({"status": 404, "type": "Error", "msg": "Hash type not found"}), 404

    message = {"status": 200, "type": "message", "msg": "OK", "hash_type": hash_row.hash_type}
    return jsonify(message)


@api.route("/v1/search", methods=["POST"])
def v1_api_search():
    if not _is_user_authorized(request):
        return redirect("/v1/not_authorized")

    search_json = request.get_json()
    if search_json and search_json.get("hash"):
        cracked_hash = Hashes.query.filter_by(cracked=True).filter_by(ciphertext=search_json["hash"]).first()
        if cracked_hash:
            msg = {
                "hash_type": cracked_hash.hash_type,
                "hash": search_json["hash"],
                "plaintext": bytes.fromhex(cracked_hash.plaintext).decode("latin-1"),
            }
            message = {"status": 200, "type": "message", "msg": msg}
        else:
            message = {"status": 200, "type": "message", "msg": "Search complete. No Results Found."}
    else:
        message = {"status": 500, "type": "message", "msg": "Invalid Search"}
    return jsonify(message)
