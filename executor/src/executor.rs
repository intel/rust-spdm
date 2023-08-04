// @file
//
// Copyright (c) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

extern crate alloc;
use {
    alloc::{boxed::Box, collections::vec_deque::VecDeque, sync::Arc},
    core::{
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    },
    spin::Mutex,
    woke::{waker_ref, Woke},
};

type TasksList = VecDeque<Box<dyn Pendable + core::marker::Send + core::marker::Sync>>;

pub struct Executor {
    tasks: Option<TasksList>,
}

trait Pendable {
    fn is_pending(&self) -> bool;
}

/// Task is our unit of execution and holds a future are waiting on
struct Task<T> {
    pub future: Mutex<Pin<Box<dyn Future<Output = T> + Send + 'static>>>,
}

/// Implement what we would like to do when a task gets woken up
impl<T> Woke for Task<T> {
    fn wake_by_ref(_: &Arc<Self>) {
        // we check if there's a lock because some immediate executing futures screw this up
        if let Some(mut e) = DEFAULT_EXECUTOR.try_lock() {
            // poll everything because future is done and may have created conditions for something to finish
            e.poll_tasks();
        }
    }
}

impl<T> Pendable for Arc<Task<T>> {
    fn is_pending(&self) -> bool {
        let mut future = self.future.lock();
        // make a waker for our task
        let waker = waker_ref(self);
        // poll our future and give it a waker
        let context = &mut Context::from_waker(&waker);
        matches!(future.as_mut().poll(context), Poll::Pending)
    }
}

impl Executor {
    // Run async task
    pub fn run<T>(&mut self, future: Pin<Box<dyn Future<Output = T> + 'static + Send>>) -> Poll<T>
    where
        T: Send + 'static,
    {
        let task = Arc::new(Task {
            future: Mutex::new(future),
        });

        let mut future = task.future.lock();
        let waker = waker_ref(&task);
        let context = &mut Context::from_waker(&waker);
        future.as_mut().poll(context)
    }

    // Run async task
    pub fn block_on<T>(&mut self, future: Pin<Box<dyn Future<Output = T> + 'static + Send>>) -> T
    where
        T: Send + 'static,
    {
        let task = Arc::new(Task {
            future: Mutex::new(future),
        });

        let mut future = task.future.lock();
        let waker = waker_ref(&task);
        let context = &mut Context::from_waker(&waker);
        loop {
            match future.as_mut().poll(context) {
                Poll::Pending => continue,
                Poll::Ready(v) => return v,
            }
        }
    }

    /// Add task for a future to the list of tasks
    pub fn add_task<T>(&mut self, future: Pin<Box<dyn Future<Output = T> + 'static + Send>>)
    where
        T: Send + 'static,
    {
        // store our task
        let task = Arc::new(Task {
            future: Mutex::new(future),
        });
        if self.tasks.is_none() {
            self.tasks = Some(TasksList::new());
        }
        let tasks: &mut TasksList = self.tasks.as_mut().expect("tasks not initialized");
        tasks.push_back(Box::new(task));
    }

    // Poll all tasks on global executor
    // output: left?
    pub fn poll_tasks(&mut self) -> bool {
        if self.tasks.is_none() {
            self.tasks = Some(TasksList::new());
        }
        let tasks: &mut TasksList = self.tasks.as_mut().expect("tasks not initialized");
        for _ in 0..tasks.len() {
            let task = tasks.pop_front().unwrap();
            if task.is_pending() {
                tasks.push_back(task);
            }
        }

        tasks.front().is_some()
    }
}

pub(crate) static DEFAULT_EXECUTOR: Mutex<Executor> = Mutex::new(Executor { tasks: None });
