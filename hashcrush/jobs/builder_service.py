"""Job builder view and context helpers."""

from __future__ import annotations

from flask import redirect, render_template, request, url_for
from sqlalchemy import select

from hashcrush.domains.service import job_domain_summaries
from hashcrush.jobs.access import _can_manage_job, _job_allows_task_mutation
from hashcrush.jobs.forms import JobSummaryForm, JobsForm, JobsNewHashFileForm
from hashcrush.jobs.queries import (
    _hashfile_rate_rows,
    _job_task_ordering,
    _ordered_job_task_names,
    _selected_hashfile_local_hits,
    _visible_hashfiles_for_job,
)
from hashcrush.models import (
    Domains,
    Hashfiles,
    Jobs,
    JobTasks,
    TaskGroups,
    Tasks,
    db,
)
from hashcrush.tasks.sorting import sort_tasks_naturally

BUILDER_TABS = {"basics", "hashes", "tasks"}
BUILDER_HASH_TABS = {"new", "existing"}


def _builder_location(job_id: int, section: str | None = None) -> str:
    if section:
        return url_for("jobs.jobs_builder", job_id=job_id, tab=section)
    return url_for("jobs.jobs_builder", job_id=job_id)


def _builder_redirect(job_id: int, section: str | None = None):
    return redirect(_builder_location(job_id, section))


def _resolve_builder_tab(raw_tab: str | None, *, job: Jobs | None) -> str:
    if raw_tab in BUILDER_TABS and (job is not None or raw_tab == "basics"):
        return raw_tab
    return "basics"


def _resolve_hashes_tab(raw_tab: str | None, *, job: Jobs | None) -> str:
    if raw_tab in BUILDER_HASH_TABS:
        return raw_tab
    if job is not None and job.hashfile_id is not None:
        return "existing"
    return "new"


def _priority_display(priority: int | None) -> str:
    labels = {
        5: "5 - highest",
        4: "4 - higher",
        3: "3 - normal",
        2: "2 - lower",
        1: "1 - lowest",
    }
    return labels.get(priority, "3 - normal")


def _build_jobs_form(*, job: Jobs | None = None, form: JobsForm | None = None) -> JobsForm:
    jobs_form = form or JobsForm()
    jobs_form.current_job_id = job.id if job else None

    if job is not None and request.method == "GET":
        jobs_form.name.data = job.name
        jobs_form.priority.data = str(job.priority)

    return jobs_form


def _job_builder_context(job: Jobs | None):
    can_manage_job = bool(job is None or _can_manage_job(job))
    can_edit_job = bool(job is not None and can_manage_job and _job_allows_task_mutation(job))

    context = {
        "hashfiles": [],
        "hashfile_cracked_rate": {},
        "selected_hashfile": None,
        "cracked_hashfiles_hashes": [],
        "job_tasks": [],
        "task_groups": [],
        "task_by_id": {},
        "available_tasks": [],
        "ordered_task_names": [],
        "cracked_rate": "0/0",
        "domain": None,
        "can_manage_job": can_manage_job,
        "can_edit_job": can_edit_job,
        "priority_display": _priority_display(job.priority) if job else None,
    }

    if job is None:
        return context

    hashfiles = _visible_hashfiles_for_job(job)
    hashfile_cracked_rate = _hashfile_rate_rows(hashfiles)
    selected_hashfile = db.session.get(Hashfiles, job.hashfile_id) if job.hashfile_id else None
    cracked_hashfiles_hashes = _selected_hashfile_local_hits(
        selected_hashfile.id if selected_hashfile else None
    )

    tasks = sort_tasks_naturally(
        db.session.execute(select(Tasks)).scalars().all()
    )
    job_tasks = db.session.execute(
        select(JobTasks).filter_by(job_id=job.id).order_by(*_job_task_ordering())
    ).scalars().all()
    task_groups = db.session.execute(
        select(TaskGroups).order_by(TaskGroups.name.asc())
    ).scalars().all()
    task_by_id = {task.id: task for task in tasks}
    assigned_task_ids = {job_task.task_id for job_task in job_tasks}
    available_tasks = [task for task in tasks if task.id not in assigned_task_ids]
    ordered_task_names = _ordered_job_task_names(job_tasks)
    domain_summary = job_domain_summaries([job.id]).get(job.id)
    effective_domain_id = domain_summary.domain_id if domain_summary else None
    domain = db.session.get(Domains, effective_domain_id) if effective_domain_id else None

    cracked_rate = "0/0"
    if selected_hashfile:
        cracked_rate = hashfile_cracked_rate.get(
            selected_hashfile.id, "(0/0)"
        ).strip("()")

    context.update(
        {
            "hashfiles": hashfiles,
            "hashfile_cracked_rate": hashfile_cracked_rate,
            "selected_hashfile": selected_hashfile,
            "cracked_hashfiles_hashes": cracked_hashfiles_hashes,
            "job_tasks": job_tasks,
            "task_groups": task_groups,
            "task_by_id": task_by_id,
            "available_tasks": available_tasks,
            "ordered_task_names": ordered_task_names,
            "cracked_rate": cracked_rate,
            "domain": domain,
        }
    )
    return context


def _render_jobs_builder(
    *,
    job: Jobs | None = None,
    jobs_form: JobsForm | None = None,
    jobs_new_hashfile_form: JobsNewHashFileForm | None = None,
    active_tab: str = "basics",
    active_hashes_tab: str | None = None,
):
    jobs_form = _build_jobs_form(job=job, form=jobs_form)
    jobs_new_hashfile_form = jobs_new_hashfile_form or JobsNewHashFileForm()
    active_tab = _resolve_builder_tab(active_tab, job=job)
    active_hashes_tab = _resolve_hashes_tab(active_hashes_tab, job=job)
    context = _job_builder_context(job)

    return render_template(
        "jobs_builder.html",
        title="Jobs",
        job=job,
        jobsForm=jobs_form,
        jobs_new_hashfile_form=jobs_new_hashfile_form,
        active_tab=active_tab,
        active_hashes_tab=active_hashes_tab,
        **context,
    )


def _render_job_review(job: Jobs, *, summary_form: JobSummaryForm | None = None):
    context = _job_builder_context(job)
    return render_template(
        "jobs_review.html",
        title="Job Summary",
        job=job,
        summary_form=summary_form or JobSummaryForm(),
        **context,
    )
