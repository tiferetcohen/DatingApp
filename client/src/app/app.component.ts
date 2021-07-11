import { NgStyle } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
//implements OnInit
export class AppComponent implements OnInit {
  title = 'The Dating App';
  users: any;

  constructor( private http: HttpClient){}
  ngOnInit(): void {
    this.getUsers();
  }

  getUsers(){
    this.http.get('https://localhost:5001/api/Users').subscribe(response => {
      this.users=response;
    }, error => {
      console.log(error);
    } );
  }
}
