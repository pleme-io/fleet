use std::collections::VecDeque;

/// Kahn's algorithm: returns execution levels (groups of step indices that can run together).
/// Each level depends only on steps in earlier levels.
pub fn topo_levels(num_steps: usize, deps: &[Vec<usize>]) -> Vec<Vec<usize>> {
    let mut in_degree = vec![0usize; num_steps];
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); num_steps];

    for (step, step_deps) in deps.iter().enumerate() {
        in_degree[step] = step_deps.len();
        for &dep in step_deps {
            dependents[dep].push(step);
        }
    }

    let mut queue: VecDeque<usize> = VecDeque::new();
    for (i, &deg) in in_degree.iter().enumerate() {
        if deg == 0 {
            queue.push_back(i);
        }
    }

    let mut levels = Vec::new();
    while !queue.is_empty() {
        let level: Vec<usize> = queue.drain(..).collect();
        for &step in &level {
            for &dep in &dependents[step] {
                in_degree[dep] -= 1;
                if in_degree[dep] == 0 {
                    queue.push_back(dep);
                }
            }
        }
        levels.push(level);
    }

    levels
}
