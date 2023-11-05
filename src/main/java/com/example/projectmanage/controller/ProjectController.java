package com.example.projectmanage.controller;
import com.example.projectmanage.model.Project;
import com.example.projectmanage.model.repository.ProjectRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping(path="/project")
public class ProjectController {

    @Autowired
    private ProjectRepository projectRepository;

    @PostMapping(path = "/create")
    public ResponseEntity<String> addNewProject(@RequestBody Project newProject) {
        projectRepository.save(newProject);
        return ResponseEntity.status(HttpStatus.CREATED).body("Project saved");
    }

    @GetMapping("/all")
    public ResponseEntity<Iterable<Project>> getAllProjects() {
        Iterable<Project> projects = projectRepository.findAll();
        return new ResponseEntity<>(projects, HttpStatus.OK);
    }

    @DeleteMapping("/{projectId}")
    public ResponseEntity<String> deleteProject(@PathVariable Integer projectId) {
        if (projectRepository.existsById(projectId)) {
            projectRepository.deleteById(projectId);
            return ResponseEntity.status(HttpStatus.NO_CONTENT).body("Project deleted");
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Project not found");
        }
    }


    @PutMapping("/{projectId}")
    public ResponseEntity<String> updateProject(@PathVariable Integer projectId, @RequestBody Project updatedProject) {
        if (projectRepository.existsById(projectId)) {
            updatedProject.setId(projectId);
            projectRepository.save(updatedProject);
            return ResponseEntity.status(HttpStatus.OK).body("Project updated");
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Project not found");
        }
    }
}

