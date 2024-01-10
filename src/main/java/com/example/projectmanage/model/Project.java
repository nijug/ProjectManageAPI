package com.example.projectmanage.model;


import jakarta.persistence.*;


import lombok.Getter;
import lombok.Setter;

import java.sql.Date;

@Getter
@Setter
@Entity
@Table(name = "projects")
public class Project {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id")
    public Integer id;

    @Column(name = "name")
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "date_started")
    private Date dateStarted;

    @Column(name = "date_ended")
    private Date dateEnded;

    @Column(name = "priority")
    private String priority;

    public Project() {
    }
}