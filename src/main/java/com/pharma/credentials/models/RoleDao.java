package com.pharma.credentials.models;

import javax.persistence.*;

@Entity
public class RoleDao {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column
    private String description;

    public RoleDao() {
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public String toString() {
        return "RoleDao{" +
                "id=" + id +
                ", description='" + description + '\'' +
                '}';
    }
}
