"""Flask routes to handle Task Groups."""

import io
import json
from datetime import UTC, datetime

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy.exc import IntegrityError

from hashcrush.models import Rules, TaskGroups, Tasks, Wordlists, db
from hashcrush.task_groups.forms import TaskGroupsForm

task_groups = Blueprint("task_groups", __name__)


def _parse_task_group_tasks(payload: str | None) -> list[int]:
    try:
        entries = json.loads(payload or "[]")
    except (TypeError, ValueError):
        return []
    if not isinstance(entries, list):
        return []
    task_ids: list[int] = []
    for entry in entries:
        try:
            parsed = int(entry)
        except (TypeError, ValueError):
            continue
        if parsed not in task_ids:
            task_ids.append(parsed)
    return task_ids


@task_groups.route("/task_groups", methods=["GET", "POST"])
@login_required
def task_groups_list():
    """Function to list task groups."""
    task_group_rows = TaskGroups.query.all()
    task_rows = Tasks.query.all()
    task_name_by_id = {task.id: task.name for task in task_rows}
    task_group_task_names = {
        task_group.id: [
            task_name_by_id[task_id]
            for task_id in _parse_task_group_tasks(task_group.tasks)
            if task_id in task_name_by_id
        ]
        for task_group in task_group_rows
    }

    return render_template(
        "task_groups.html",
        title="Task Groups",
        task_groups=task_group_rows,
        tasks=task_rows,
        task_group_task_names=task_group_task_names,
    )


@task_groups.route("/task_groups/export", methods=["GET"])
@login_required
def task_groups_export():
    """Export shared tasks/task-groups as JSON."""
    shared_tasks = Tasks.query.order_by(Tasks.id.asc()).all()
    shared_task_groups = TaskGroups.query.order_by(TaskGroups.id.asc()).all()

    visible_wordlists = {row.id: row.name for row in Wordlists.query.all()}
    visible_rules = {row.id: row.name for row in Rules.query.all()}
    shared_task_name_by_id = {task.id: task.name for task in shared_tasks}

    export_tasks = []
    for task in shared_tasks:
        export_tasks.append(
            {
                "name": task.name,
                "hc_attackmode": task.hc_attackmode,
                "hc_mask": task.hc_mask,
                "wordlist_name": visible_wordlists.get(task.wl_id),
                "rule_name": visible_rules.get(task.rule_id),
            }
        )

    export_task_groups = []
    for task_group in shared_task_groups:
        task_names: list[str] = []
        for task_id in _parse_task_group_tasks(task_group.tasks):
            task_name = shared_task_name_by_id.get(task_id)
            if task_name:
                task_names.append(task_name)
        export_task_groups.append(
            {
                "name": task_group.name,
                "tasks": task_names,
            }
        )

    payload = {
        "version": 1,
        "exported_at_utc": datetime.now(UTC)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "exported_by": current_user.username,
        "tasks": export_tasks,
        "task_groups": export_task_groups,
    }

    buffer = io.BytesIO(json.dumps(payload, indent=2).encode("utf-8"))
    buffer.seek(0)
    filename = f"task_groups_export_{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/json",
    )


@task_groups.route("/task_groups/import", methods=["POST"])
@login_required
def task_groups_import():
    """Import tasks/task-groups from JSON into shared resource data."""
    upload = request.files.get("import_file")
    if not upload or not upload.filename:
        flash("Select a JSON file to import.", "danger")
        return redirect(url_for("task_groups.task_groups_list"))

    try:
        payload = json.loads(upload.read().decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        flash("Invalid JSON file.", "danger")
        return redirect(url_for("task_groups.task_groups_list"))

    if not isinstance(payload, dict):
        flash("Invalid import payload format.", "danger")
        return redirect(url_for("task_groups.task_groups_list"))

    tasks_payload = payload.get("tasks", [])
    groups_payload = payload.get("task_groups", [])
    if not isinstance(tasks_payload, list) or not isinstance(groups_payload, list):
        flash("Invalid import payload format.", "danger")
        return redirect(url_for("task_groups.task_groups_list"))

    wordlists_by_name = {row.name: row.id for row in Wordlists.query.all()}
    rules_by_name = {row.name: row.id for row in Rules.query.all()}

    shared_tasks = {row.name: row for row in Tasks.query.all()}
    shared_task_groups = {row.name: row for row in TaskGroups.query.all()}

    created_tasks = 0
    updated_tasks = 0
    skipped_tasks = 0
    created_groups = 0
    updated_groups = 0
    skipped_groups = 0

    try:
        for task_entry in tasks_payload:
            if not isinstance(task_entry, dict):
                skipped_tasks += 1
                continue

            task_name = str(task_entry.get("name") or "").strip()
            attack_mode = str(task_entry.get("hc_attackmode") or "").strip()
            if not task_name or attack_mode not in {"dictionary", "maskmode"}:
                skipped_tasks += 1
                continue

            wl_id = None
            rule_id = None
            task_mask = None

            if attack_mode == "dictionary":
                wordlist_name = str(task_entry.get("wordlist_name") or "").strip()
                if not wordlist_name:
                    skipped_tasks += 1
                    continue

                wl_id = wordlists_by_name.get(wordlist_name)
                if wl_id is None:
                    skipped_tasks += 1
                    continue

                rule_name = str(task_entry.get("rule_name") or "").strip()
                if rule_name:
                    rule_id = rules_by_name.get(rule_name)
                    if rule_id is None:
                        skipped_tasks += 1
                        continue
            else:
                task_mask = str(task_entry.get("hc_mask") or "").strip()
                if not task_mask:
                    skipped_tasks += 1
                    continue

            target_task = shared_tasks.get(task_name)
            if target_task:
                updated_tasks += 1
            else:
                target_task = Tasks(
                    name=task_name,
                    hc_attackmode=attack_mode,
                    wl_id=None,
                    rule_id=None,
                    hc_mask=None,
                )
                db.session.add(target_task)
                created_tasks += 1

            target_task.name = task_name
            target_task.hc_attackmode = attack_mode
            target_task.wl_id = wl_id
            target_task.rule_id = rule_id
            target_task.hc_mask = task_mask

            db.session.flush()
            shared_tasks[target_task.name] = target_task

        for group_entry in groups_payload:
            if not isinstance(group_entry, dict):
                skipped_groups += 1
                continue

            group_name = str(group_entry.get("name") or "").strip()
            raw_task_names = group_entry.get("tasks") or []
            if (not group_name) or (not isinstance(raw_task_names, list)):
                skipped_groups += 1
                continue

            task_ids: list[int] = []
            for task_name_entry in raw_task_names:
                task_name = str(task_name_entry or "").strip()
                if not task_name:
                    continue
                matched_task = shared_tasks.get(task_name)
                if matched_task and matched_task.id not in task_ids:
                    task_ids.append(matched_task.id)

            target_group = shared_task_groups.get(group_name)
            if target_group:
                updated_groups += 1
            else:
                target_group = TaskGroups(
                    name=group_name,
                    tasks=json.dumps([]),
                )
                db.session.add(target_group)
                created_groups += 1

            target_group.name = group_name
            target_group.tasks = json.dumps(task_ids)
            db.session.flush()
            shared_task_groups[target_group.name] = target_group

        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash(
            "Import failed because one or more task or task-group names changed concurrently. Refresh and retry.",
            "danger",
        )
        return redirect(url_for("task_groups.task_groups_list"))
    except Exception:
        db.session.rollback()
        flash("Import failed due to an internal error.", "danger")
        return redirect(url_for("task_groups.task_groups_list"))

    flash(
        (
            "Import complete. "
            f"Tasks created: {created_tasks}, updated: {updated_tasks}, skipped: {skipped_tasks}. "
            f"Groups created: {created_groups}, updated: {updated_groups}, skipped: {skipped_groups}."
        ),
        "success",
    )
    return redirect(url_for("task_groups.task_groups_list"))


@task_groups.route("/task_groups/add", methods=["GET", "POST"])
@login_required
def task_groups_add():
    """Function to add task group."""
    task_group_form = TaskGroupsForm()
    task_rows = Tasks.query.all()
    if task_group_form.validate_on_submit():
        task_group = TaskGroups(
            name=task_group_form.name.data,
            tasks=json.dumps([]),
        )
        db.session.add(task_group)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash(
                "Task group could not be created because that name already exists. Refresh and retry.",
                "danger",
            )
            return render_template(
                "task_groups_add.html",
                title="Task Group Add",
                tasks=task_rows,
                taskGroupsForm=task_group_form,
            )
        flash(f"Task group {task_group_form.name.data} created!", "success")
        # Keep a direct redirect here to preserve current route behavior.
        return redirect("assigned_tasks/" + str(task_group.id))
    return render_template(
        "task_groups_add.html",
        title="Task Group Add",
        tasks=task_rows,
        taskGroupsForm=task_group_form,
    )


@task_groups.route(
    "/task_groups/assigned_tasks/<int:task_group_id>", methods=["GET", "POST"]
)
@login_required
def task_groups_assigned_tasks(task_group_id):
    """Function to list assigned tasks for task group."""
    task_group = TaskGroups.query.get_or_404(task_group_id)
    task_rows = Tasks.query.all()
    task_group_tasks = _parse_task_group_tasks(task_group.tasks)
    return render_template(
        "task_groups_assigntask.html",
        title="Task Group: Assign Tasks",
        task_group=task_group,
        tasks=task_rows,
        task_group_tasks=task_group_tasks,
    )


@task_groups.route(
    "/task_groups/assigned_tasks/<int:task_group_id>/add_task/<int:task_id>",
    methods=["POST"],
)
@login_required
def task_groups_assigned_tasks_add_task(task_group_id, task_id):
    """Function to assign task to task group."""
    task_group = TaskGroups.query.get_or_404(task_group_id)
    task = Tasks.query.filter(Tasks.id == task_id).first_or_404()
    task_group_tasks = _parse_task_group_tasks(task_group.tasks)
    if task.id not in task_group_tasks:
        task_group_tasks.append(task.id)
    task_group.tasks = json.dumps(task_group_tasks)
    db.session.commit()
    return redirect("/task_groups/assigned_tasks/" + str(task_group.id))


@task_groups.route(
    "/task_groups/assigned_tasks/<int:task_group_id>/remove_task/<int:task_id>",
    methods=["POST"],
)
@login_required
def task_groups_assigned_tasks_remove_task(task_group_id, task_id):
    """Function to remove task from task group."""
    task_group = TaskGroups.query.get_or_404(task_group_id)
    task_group_tasks = _parse_task_group_tasks(task_group.tasks)
    if task_id not in task_group_tasks:
        flash("Task is not assigned to this group.", "warning")
        return redirect("/task_groups/assigned_tasks/" + str(task_group.id))

    task_group_tasks.remove(task_id)
    task_group.tasks = json.dumps(task_group_tasks)
    db.session.commit()
    return redirect("/task_groups/assigned_tasks/" + str(task_group.id))


@task_groups.route(
    "/task_groups/assigned_tasks/<int:task_group_id>/promote_task/<int:task_id>",
    methods=["POST"],
)
@login_required
def task_groups_assigned_tasks_promote_task(task_group_id, task_id):
    """Function to move assigned task up higher in queue on task group."""
    task_group = TaskGroups.query.get_or_404(task_group_id)
    task_group_tasks = _parse_task_group_tasks(task_group.tasks)
    if not task_group_tasks or task_id not in task_group_tasks:
        flash("Task is not assigned to this group.", "warning")
        return redirect("/task_groups/assigned_tasks/" + str(task_group.id))

    if task_group_tasks[0] == task_id:
        # Cant promote further
        return redirect("/task_groups/assigned_tasks/" + str(task_group.id))

    new_task_group_tasks = []
    # Creating manual index since for-loop does not allow iterator mutation.
    index = 0
    while index < len(task_group_tasks):
        if index + 1 < len(task_group_tasks):
            if task_group_tasks[index + 1] == task_id:
                new_task_group_tasks.append(task_id)
                new_task_group_tasks.append(task_group_tasks[index])
                index = index + 1
            else:
                new_task_group_tasks.append(task_group_tasks[index])
        else:
            new_task_group_tasks.append(task_group_tasks[index])
        index += 1
    task_group.tasks = json.dumps(new_task_group_tasks)
    db.session.commit()
    return redirect("/task_groups/assigned_tasks/" + str(task_group.id))


@task_groups.route(
    "/task_groups/assigned_tasks/<int:task_group_id>/demote_task/<int:task_id>",
    methods=["POST"],
)
@login_required
def task_groups_assigned_tasks_demote_task(task_group_id, task_id):
    """Function to move assigned task lower in queue on task group."""
    task_group = TaskGroups.query.get_or_404(task_group_id)
    task_group_tasks = _parse_task_group_tasks(task_group.tasks)
    if not task_group_tasks or task_id not in task_group_tasks:
        flash("Task is not assigned to this group.", "warning")
        return redirect("/task_groups/assigned_tasks/" + str(task_group.id))

    if task_group_tasks[-1] == task_id:
        # Cant demote further
        return redirect("/task_groups/assigned_tasks/" + str(task_group.id))

    new_task_group_tasks = []
    # Creating manual index since for-loop does not allow iterator mutation.
    index = 0
    while index < len(task_group_tasks):
        if index + 1 < len(task_group_tasks):
            if task_group_tasks[index] == task_id:
                new_task_group_tasks.append(task_group_tasks[index + 1])
                new_task_group_tasks.append(task_id)
                index = index + 1
            else:
                new_task_group_tasks.append(task_group_tasks[index])
        else:
            new_task_group_tasks.append(task_group_tasks[index])
        index += 1
    task_group.tasks = json.dumps(new_task_group_tasks)
    db.session.commit()
    return redirect("/task_groups/assigned_tasks/" + str(task_group.id))


@task_groups.route("/task_groups/delete/<int:task_group_id>", methods=["POST"])
@login_required
def task_groups_delete(task_group_id):
    """Function to delete task group."""
    task_group = TaskGroups.query.get_or_404(task_group_id)
    db.session.delete(task_group)
    db.session.commit()
    flash("Task Group has been deleted!", "success")
    return redirect(url_for("task_groups.task_groups_list"))
