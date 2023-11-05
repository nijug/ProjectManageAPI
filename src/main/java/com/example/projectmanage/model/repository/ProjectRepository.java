package com.example.projectmanage.model.repository;

import com.example.projectmanage.model.Project;
import org.springframework.data.repository.CrudRepository;

public interface ProjectRepository extends CrudRepository<Project, Integer> {

}