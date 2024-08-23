package com.example.Spring_Login_Eg3.repository;

import com.example.Spring_Login_Eg3.entity.Course;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CourseRepository extends JpaRepository<Course, Integer> {
}
